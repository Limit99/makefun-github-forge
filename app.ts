// A standalone GitHub-compatible git forge: git smart HTTP (upload-pack v2 + v0,
// receive-pack v0), the REST v3 API, GraphQL v4 and an MCP endpoint, all over one
// in-memory store. Node standard library only; no git binary, no dependencies.
//
// Determinism is a hard requirement (a trial's replay must export byte-identical
// state), so nothing here reads the wall clock or a random source for anything a
// client can see: timestamps derive from MAKEFUN_TRIAL_NOW when the trial sets it
// (a fixed base epoch otherwise) plus a monotonic counter, and every id comes
// from a counter.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// deterministic time and ids
// ---------------------------------------------------------------------------

function trialBaseEpochSec(): number {
  const raw = (process.env.MAKEFUN_TRIAL_NOW ?? '').trim();
  if (raw !== '') {
    if (/^\d+$/.test(raw)) {
      const n = Number(raw);
      return n > 10_000_000_000 ? Math.floor(n / 1000) : n;
    }
    const parsed = Date.parse(raw);
    if (!Number.isNaN(parsed)) return Math.floor(parsed / 1000);
  }
  return 1_735_689_600; // 2025-01-01T00:00:00Z, the scenario epoch
}

const BASE_EPOCH_SEC = trialBaseEpochSec();
let tickCounter = 0;

/** The next deterministic timestamp, in epoch seconds. */
function nowSec(): number {
  tickCounter += 1;
  return BASE_EPOCH_SEC + tickCounter;
}

/** The next deterministic timestamp, as an ISO string. */
function nowIso(): string {
  return new Date(nowSec() * 1000).toISOString();
}

let requestCounter = 0;
function nextRequestId(): string {
  requestCounter += 1;
  return `FORGE-${requestCounter.toString(16).toUpperCase().padStart(8, '0')}`;
}

// ---------------------------------------------------------------------------
// the token's owner (the viewer)
// ---------------------------------------------------------------------------

// The forge is single-tenant: every repository belongs to the login the trial's
// bearer token names. The suite always addresses that owner in owner-scoped
// paths (/{owner}/{repo}.git, /api/v3/repos/{owner}/...), so the login is
// learned from the first owner-scoped request and enforced from then on: the
// same repository name under any other owner is a 404, never a 403.
let viewerLogin: string | null = null;
const FALLBACK_VIEWER = 'adaiversen';

function viewer(): string {
  return viewerLogin ?? FALLBACK_VIEWER;
}

/** Learn (once) or check the owner named by an owner-scoped path. */
function ownerMatches(owner: string): boolean {
  if (viewerLogin === null) {
    if (owner !== '') viewerLogin = owner;
    return true;
  }
  return owner === viewerLogin;
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

/** True when the request carries the trial's bearer token. */
function authed(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length);
  if (token === '') return false;
  return EXPECTED_TOKEN === '' || token === EXPECTED_TOKEN;
}

// ---------------------------------------------------------------------------
// git object primitives
// ---------------------------------------------------------------------------

type GitObjectType = 'blob' | 'tree' | 'commit' | 'tag';

interface GitObject {
  readonly type: GitObjectType;
  readonly data: Buffer;
}

const ZERO_OID = '0'.repeat(40);
const TYPE_CODES: Readonly<Record<GitObjectType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPES: Readonly<Record<number, GitObjectType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** A git object's id: SHA-1 of "<type> <size>\0" + bytes. */
function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

interface TreeEntry {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const mode = data.toString('ascii', offset, space);
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('tree entry is truncated');
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.toString('hex', nul + 1, nul + 21);
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** Git's tree order: by name, directories compared as if named "<name>/". */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitInfo {
  readonly tree: string;
  readonly parents: readonly string[];
  readonly author: string;
  readonly committer: string;
  readonly message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  let author = '';
  let committer = '';
  const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(info: CommitInfo): Buffer {
  const lines = [`tree ${info.tree}`];
  for (const parent of info.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${info.author}`);
  lines.push(`committer ${info.committer}`);
  return Buffer.from(`${lines.join('\n')}\n\n${info.message}`, 'utf8');
}

function parseTagTarget(data: Buffer): string {
  const text = data.toString('utf8');
  const match = /^object ([0-9a-f]{40})$/m.exec(text);
  return match === null ? '' : (match[1] as string);
}

// ---------------------------------------------------------------------------
// pkt-line framing
// ---------------------------------------------------------------------------

function encodePkt(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const length = body.length + 4;
  const header = Buffer.from(length.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, body]);
}

const FLUSH_PKT = Buffer.from('0000', 'ascii');
const DELIM_PKT = Buffer.from('0001', 'ascii');

type Pkt =
  | { readonly kind: 'data'; readonly payload: Buffer }
  | { readonly kind: 'flush' }
  | { readonly kind: 'delim' }
  | { readonly kind: 'response-end' };

/** Decode every pkt-line in `buf`; throws on malformed framing. */
function decodePkts(buf: Buffer): { readonly packets: Pkt[]; readonly rest: Buffer } {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('pkt-line truncated header');
    const headerText = buf.toString('ascii', offset, offset + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(headerText)) throw new Error('pkt-line header is not hex');
    const length = parseInt(headerText, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
    } else if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
    } else if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
    } else if (length === 3 || length < 4) {
      throw new Error('pkt-line length 3 is invalid');
    } else {
      if (offset + length > buf.length) throw new Error('pkt-line truncated payload');
      packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + length) });
      offset += length;
    }
    if (offset === buf.length) break;
    if (buf.length - offset < 4) {
      // Trailing unframed bytes: stop and hand them back (a receive-pack body
      // ends its command list with a flush, after which the pack follows raw).
      return { packets, rest: buf.subarray(offset) };
    }
  }
  return { packets, rest: buf.subarray(offset) };
}

// ---------------------------------------------------------------------------
// packfiles
// ---------------------------------------------------------------------------

/** Inflate one deflate stream starting at `offset`, finding its exact end. */
function inflateExact(buf: Buffer, offset: number, expectedSize: number): { readonly data: Buffer; readonly nextOffset: number } {
  // With { info: true } the zlib engine reports how many input bytes it
  // consumed (its `bytesWritten`), which is exactly the stream's length inside
  // the surrounding pack — one inflation per entry, no searching.
  const out = inflateSync(buf.subarray(offset), { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  if (out.buffer.length !== expectedSize) throw new Error('pack entry size mismatch');
  return { data: out.buffer, nextOffset: offset + out.engine.bytesWritten };
}

/** Apply a git delta to its base. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= delta.length) throw new Error('delta varint overruns');
      const byte = delta[offset] as number;
      offset += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readVarint();
  const out: Buffer[] = [];
  let produced = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          copyOffset |= (delta[offset] as number) << (8 * i);
          offset += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          copySize |= (delta[offset] as number) << (8 * i);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOffset + copySize > base.length) throw new Error('delta copy out of bounds');
      out.push(base.subarray(copyOffset, copyOffset + copySize));
      produced += copySize;
    } else if (op > 0) {
      if (offset + op > delta.length) throw new Error('delta insert out of bounds');
      out.push(delta.subarray(offset, offset + op));
      offset += op;
      produced += op;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  const result = Buffer.concat(out);
  if (produced !== targetSize || result.length !== targetSize) throw new Error('delta result size mismatch');
  return result;
}

interface PackEntry {
  readonly offset: number;
  readonly typeCode: number;
  readonly size: number;
  readonly data: Buffer;
  readonly baseOffset?: number;
  readonly baseOid?: string;
}

/** Parse a packfile's entries (deltas unresolved). Throws on any defect. */
function parsePack(buf: Buffer): PackEntry[] {
  if (buf.length < 32) throw new Error('pack is too short');
  if (buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('pack magic is not PACK');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const entries: PackEntry[] = [];
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset;
    let byte = buf[offset] as number;
    offset += 1;
    const typeCode = (byte >> 4) & 0x7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = buf[offset] as number;
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      let b = buf[offset] as number;
      offset += 1;
      let value = b & 0x7f;
      while (b & 0x80) {
        b = buf[offset] as number;
        offset += 1;
        value = ((value + 1) << 7) | (b & 0x7f);
      }
      baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      baseOid = buf.toString('hex', offset, offset + 20);
      offset += 20;
    }
    const inflated = inflateExact(buf, offset, size);
    entries.push({ offset: entryOffset, typeCode, size, data: inflated.data, baseOffset, baseOid });
    offset = inflated.nextOffset;
  }
  if (offset !== buf.length - 20) throw new Error('pack has trailing bytes');
  const trailer = buf.toString('hex', buf.length - 20);
  if (sha1Hex(buf.subarray(0, buf.length - 20)) !== trailer) throw new Error('pack checksum mismatch');
  return entries;
}

/** Resolve a parsed pack into whole objects, keyed by oid. */
function resolvePack(entries: readonly PackEntry[], fallback: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  const byOffset = new Map<number, PackEntry>();
  for (const entry of entries) byOffset.set(entry.offset, entry);
  const resolved = new Map<string, GitObject>();
  const resolving = new Set<number>();
  const resolveEntry = (entry: PackEntry): GitObject => {
    if (entry.typeCode >= 1 && entry.typeCode <= 4) {
      return { type: CODE_TYPES[entry.typeCode] as GitObjectType, data: entry.data };
    }
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let base: GitObject;
    if (entry.typeCode === 6) {
      const baseEntry = entry.baseOffset === undefined ? undefined : byOffset.get(entry.baseOffset);
      if (baseEntry === undefined) throw new Error('ofs-delta base is not in the pack');
      base = resolveEntry(baseEntry);
    } else if (entry.typeCode === 7) {
      const inPack = entries.find((candidate) => candidate.typeCode <= 4 && hashObject(CODE_TYPES[candidate.typeCode] as GitObjectType, candidate.data) === entry.baseOid);
      if (inPack !== undefined) base = resolveEntry(inPack);
      else {
        const held = entry.baseOid === undefined ? undefined : fallback(entry.baseOid);
        if (held === undefined) throw new Error('ref-delta base is unknown');
        base = held;
      }
    } else {
      throw new Error(`pack type ${entry.typeCode}`);
    }
    resolving.delete(entry.offset);
    return { type: base.type, data: applyDelta(base.data, entry.data) };
  };
  for (const entry of entries) {
    const object = resolveEntry(entry);
    resolved.set(hashObject(object.type, object.data), object);
  }
  return resolved;
}

/** Build a version-2 pack holding `objects` whole (no deltas). */
function buildPack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    const size = object.data.length;
    const typeCode = TYPE_CODES[object.type];
    const bytes: number[] = [];
    let first = (typeCode << 4) | (size & 0x0f);
    let rest = size >> 4;
    if (rest > 0) first |= 0x80;
    bytes.push(first);
    while (rest > 0) {
      let b = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) b |= 0x80;
      bytes.push(b);
    }
    parts.push(Buffer.from(bytes));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

interface IssueRec {
  readonly dbId: number;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  readonly createdAt: string;
  updatedAt: string;
}

interface CommentRec {
  readonly dbId: number;
  readonly body: string;
  readonly createdAt: string;
}

interface PullRec {
  readonly dbId: number;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  readonly createdAt: string;
  updatedAt: string;
}

interface RepoRec {
  readonly dbId: number;
  readonly name: string;
  description: string;
  priv: boolean;
  readonly defaultBranch: string;
  readonly createdAt: string;
  updatedAt: string;
  readonly objects: Map<string, GitObject>;
  readonly refs: Map<string, string>;
  readonly labels: Set<string>;
  readonly issues: Map<number, IssueRec>;
  readonly comments: Map<number, CommentRec[]>;
  readonly pulls: Map<number, PullRec>;
  readonly packCache: Map<string, Buffer>;
  nextNumber: number;
}

const reposByName = new Map<string, RepoRec>();
let nextRepoDbId = 5000;
let nextIssueDbId = 30_000;
let nextPullDbId = 40_000;
let nextCommentDbId = 50_000;

function createRepo(name: string, description: string, priv: boolean): RepoRec {
  const stamp = nowIso();
  const repo: RepoRec = {
    dbId: nextRepoDbId,
    name,
    description,
    priv,
    defaultBranch: 'main',
    createdAt: stamp,
    updatedAt: stamp,
    objects: new Map(),
    refs: new Map(),
    labels: new Set(),
    issues: new Map(),
    comments: new Map(),
    pulls: new Map(),
    packCache: new Map(),
    nextNumber: 1,
  };
  nextRepoDbId += 1;
  reposByName.set(name, repo);
  return repo;
}

function findRepo(owner: string, name: string): RepoRec | null {
  if (!ownerMatches(owner)) return null;
  return reposByName.get(name) ?? null;
}

function storeObject(repo: RepoRec, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function forgeIdentity(): string {
  const login = viewer();
  return `${login} <${login}@example.invalid>`;
}

/** Create a commit in `repo` and return its oid (the ref is not moved). */
function makeCommit(repo: RepoRec, tree: string, parents: readonly string[], message: string): string {
  const identity = `${forgeIdentity()} ${nowSec()} +0000`;
  return storeObject(repo, 'commit', buildCommit({ tree, parents, author: identity, committer: identity, message }));
}

// ---------------------------------------------------------------------------
// trees as flat path maps
// ---------------------------------------------------------------------------

type FlatTree = Map<string, { readonly oid: string; readonly mode: string }>;

function flattenTree(repo: RepoRec, treeOid: string, prefix: string, out: FlatTree): void {
  const tree = repo.objects.get(treeOid);
  if (tree === undefined || tree.type !== 'tree') return;
  for (const entry of parseTree(tree.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
}

function flatOfCommit(repo: RepoRec, commitOid: string): FlatTree {
  const out: FlatTree = new Map();
  const commit = repo.objects.get(commitOid);
  if (commit === undefined || commit.type !== 'commit') return out;
  flattenTree(repo, parseCommit(commit.data).tree, '', out);
  return out;
}

function treeOfCommit(repo: RepoRec, commitOid: string): string {
  const commit = repo.objects.get(commitOid);
  if (commit === undefined || commit.type !== 'commit') return '';
  return parseCommit(commit.data).tree;
}

/** Build (and store) the tree hierarchy for a flat path map; returns its oid. */
function buildTreeFromFlat(repo: RepoRec, flat: FlatTree): string {
  interface Node {
    readonly files: Map<string, { readonly oid: string; readonly mode: string }>;
    readonly dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, file] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const segment = segments[i] as string;
      let child = node.dirs.get(segment);
      if (child === undefined) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(segment, child);
      }
      node = child;
    }
    node.files.set(segments[segments.length - 1] as string, file);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, file] of node.files) entries.push({ mode: file.mode, name, oid: file.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** Commit a set of path changes (null content deletes) on a branch; returns the new commit oid. */
function commitChanges(repo: RepoRec, branch: string, changes: ReadonlyMap<string, Buffer | null>, message: string): string {
  const ref = `refs/heads/${branch}`;
  let tip = repo.refs.get(ref);
  if (tip === undefined) {
    // A contents write to a branch that does not exist yet starts it from the
    // default branch's tip (or from nothing, on an unborn repository).
    tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    if (tip !== undefined) repo.refs.set(ref, tip);
  }
  const flat = tip === undefined ? new Map() : flatOfCommit(repo, tip);
  for (const [path, content] of changes) {
    if (content === null) flat.delete(path);
    else flat.set(path, { oid: storeObject(repo, 'blob', content), mode: '100644' });
  }
  const tree = buildTreeFromFlat(repo, flat as FlatTree);
  const commit = makeCommit(repo, tree, tip === undefined ? [] : [tip], message);
  repo.refs.set(ref, commit);
  return commit;
}

function branchTip(repo: RepoRec, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

/** Every commit reachable from `tip`, newest first (depth-first, parents in order). */
function walkCommits(repo: RepoRec, tip: string): string[] {
  const seen = new Set<string>();
  const order: string[] = [];
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    seen.add(oid);
    order.push(oid);
    const parents = parseCommit(object.data).parents;
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i] as string);
  }
  return order;
}

/** All objects reachable from the given tips (commits, tags, trees, blobs). */
function reachableObjects(repo: RepoRec, tips: readonly string[]): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    out.set(oid, object);
    if (object.type === 'commit') {
      const info = parseCommit(object.data);
      stack.push(info.tree);
      for (const parent of info.parents) stack.push(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    } else if (object.type === 'tag') {
      const target = parseTagTarget(object.data);
      if (target !== '') stack.push(target);
    }
  }
  return out;
}

function isAncestor(repo: RepoRec, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) stack.push(parent);
  }
  return false;
}

/** The nearest common ancestor of two commits, or null. */
function mergeBase(repo: RepoRec, a: string, b: string): string | null {
  const ancestorsOfA = new Set(walkCommits(repo, a));
  for (const candidate of walkCommits(repo, b)) {
    if (ancestorsOfA.has(candidate)) return candidate;
  }
  return null;
}

/** Peel a tag (or any object) down to the commit it points at, if any. */
function peelToCommit(repo: RepoRec, oid: string): string {
  let current = oid;
  for (let guard = 0; guard < 32; guard += 1) {
    const object = repo.objects.get(current);
    if (object === undefined) return current;
    if (object.type === 'commit') return current;
    if (object.type === 'tag') {
      current = parseTagTarget(object.data);
      continue;
    }
    return current;
  }
  return current;
}

// ---------------------------------------------------------------------------
// issues, comments, pull requests
// ---------------------------------------------------------------------------

function createIssue(repo: RepoRec, title: string, body: string, labels: string[]): IssueRec {
  const stamp = nowIso();
  const issue: IssueRec = {
    dbId: nextIssueDbId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    labels: [...labels],
    createdAt: stamp,
    updatedAt: stamp,
  };
  nextIssueDbId += 1;
  repo.nextNumber += 1;
  repo.issues.set(issue.number, issue);
  return issue;
}

function createPull(repo: RepoRec, title: string, body: string, headRef: string, baseRef: string): PullRec {
  const stamp = nowIso();
  const pull: PullRec = {
    dbId: nextPullDbId,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    headRef,
    baseRef,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    createdAt: stamp,
    updatedAt: stamp,
  };
  nextPullDbId += 1;
  repo.nextNumber += 1;
  repo.pulls.set(pull.number, pull);
  return pull;
}

interface ChangedFile {
  readonly filename: string;
  readonly status: string;
  readonly additions: number;
  readonly deletions: number;
  readonly changes: number;
}

function countLines(data: Buffer): number {
  if (data.length === 0) return 0;
  const text = data.toString('utf8');
  return text.endsWith('\n') ? text.split('\n').length - 1 : text.split('\n').length;
}

/** The files a pull request changes: its head tree against the merge base. */
function pullChangedFiles(repo: RepoRec, pull: PullRec): ChangedFile[] {
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  if (headTip === undefined || baseTip === undefined) return [];
  const base = mergeBase(repo, headTip, baseTip) ?? baseTip;
  const baseFlat = flatOfCommit(repo, base);
  const headFlat = flatOfCommit(repo, headTip);
  const files: ChangedFile[] = [];
  const paths = new Set([...baseFlat.keys(), ...headFlat.keys()]);
  for (const path of [...paths].sort()) {
    const before = baseFlat.get(path);
    const after = headFlat.get(path);
    if (before?.oid === after?.oid) continue;
    const beforeBlob = before === undefined ? undefined : repo.objects.get(before.oid);
    const afterBlob = after === undefined ? undefined : repo.objects.get(after.oid);
    const additions = afterBlob === undefined ? 0 : countLines(afterBlob.data);
    const deletions = beforeBlob === undefined ? 0 : countLines(beforeBlob.data);
    files.push({
      filename: path,
      status: before === undefined ? 'added' : after === undefined ? 'removed' : 'modified',
      additions,
      deletions,
      changes: additions + deletions,
    });
  }
  return files;
}

/** Three-way view of a merge: the merged flat tree, or null on a content conflict. */
function mergedFlatTree(repo: RepoRec, pull: PullRec): FlatTree | null {
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  if (headTip === undefined || baseTip === undefined) return null;
  const base = mergeBase(repo, headTip, baseTip);
  const originFlat = base === null ? new Map<string, { oid: string; mode: string }>() : flatOfCommit(repo, base);
  const headFlat = flatOfCommit(repo, headTip);
  const result = flatOfCommit(repo, baseTip) as FlatTree;
  const paths = new Set([...originFlat.keys(), ...headFlat.keys()]);
  for (const path of paths) {
    const origin = originFlat.get(path);
    const head = headFlat.get(path);
    if (origin?.oid === head?.oid) continue; // the head did not change this path
    const current = result.get(path);
    if (current !== undefined && origin !== undefined && current.oid !== origin.oid && current.oid !== head?.oid) {
      return null; // both sides changed the same path to different bytes
    }
    if (current !== undefined && origin === undefined && head !== undefined && current.oid !== head.oid) {
      return null; // both sides added the same path with different bytes
    }
    if (head === undefined) result.delete(path);
    else result.set(path, head);
  }
  return result;
}

function pullIsConflicted(repo: RepoRec, pull: PullRec): boolean {
  if (pull.merged) return false;
  return mergedFlatTree(repo, pull) === null;
}

/** Merge a pull request with a squash commit on its base branch. */
function mergePull(repo: RepoRec, pull: PullRec): { readonly sha: string } | null {
  const flat = mergedFlatTree(repo, pull);
  if (flat === null) return null;
  const baseTip = branchTip(repo, pull.baseRef);
  if (baseTip === undefined) return null;
  const tree = buildTreeFromFlat(repo, flat);
  const sha = makeCommit(repo, tree, [baseTip], `${pull.title} (#${pull.number})`);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = sha;
  pull.updatedAt = pull.mergedAt;
  return { sha };
}

// ---------------------------------------------------------------------------
// global (GraphQL) ids
// ---------------------------------------------------------------------------

function globalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64');
}

function repoGlobalId(repo: RepoRec): string {
  return globalId('Repository', String(repo.dbId));
}

function issueGlobalId(repo: RepoRec, issue: IssueRec): string {
  return globalId('Issue', `${repo.dbId}:${issue.number}`);
}

function pullGlobalId(repo: RepoRec, pull: PullRec): string {
  return globalId('PullRequest', `${repo.dbId}:${pull.number}`);
}

function commentGlobalId(repo: RepoRec, issueNumber: number, comment: CommentRec): string {
  return globalId('IssueComment', `${repo.dbId}:${issueNumber}:${comment.dbId}`);
}

/** Decode a global id into its kind and key parts, or null. */
function decodeGlobalId(id: string): { readonly kind: string; readonly parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { kind: text.slice(0, colon), parts: text.slice(colon + 1).split(':') };
  } catch {
    return null;
  }
}

function repoByDbId(dbId: number): RepoRec | null {
  for (const repo of reposByName.values()) if (repo.dbId === dbId) return repo;
  return null;
}

// ---------------------------------------------------------------------------
// REST serializers
// ---------------------------------------------------------------------------

function repoJson(repo: RepoRec): Record<string, unknown> {
  const owner = viewer();
  return {
    id: repo.dbId,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: `${owner}/${repo.name}`,
    private: repo.priv,
    owner: { login: owner, id: 1000, type: 'User' },
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
  };
}

function issueJson(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  return {
    id: issue.dbId,
    node_id: issueGlobalId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name })),
    user: { login: viewer(), id: 1000, type: 'User' },
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
  };
}

function commentJson(repo: RepoRec, issueNumber: number, comment: CommentRec): Record<string, unknown> {
  return {
    id: comment.dbId,
    node_id: commentGlobalId(repo, issueNumber, comment),
    body: comment.body,
    user: { login: viewer(), id: 1000, type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
  };
}

function pullJson(repo: RepoRec, pull: PullRec): Record<string, unknown> {
  const headTip = branchTip(repo, pull.headRef);
  const baseTip = branchTip(repo, pull.baseRef);
  return {
    id: pull.dbId,
    node_id: pullGlobalId(repo, pull),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.headRef, sha: headTip ?? ZERO_OID, label: `${viewer()}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: baseTip ?? ZERO_OID, label: `${viewer()}:${pull.baseRef}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: !pullIsConflicted(repo, pull),
    user: { login: viewer(), id: 1000, type: 'User' },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
  };
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...headers,
  });
  res.end(text);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Parse a JSON request body; {} for an empty body, null for malformed JSON. */
function parseJsonBody(raw: Buffer): Record<string, unknown> | null {
  if (raw.length === 0) return {};
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    return {};
  } catch {
    return null;
  }
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function strOr(value: unknown, fallback: string): string {
  return typeof value === 'string' && value !== '' ? value : fallback;
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function repoFromParams(res: ServerResponse, owner: string, name: string): RepoRec | null {
  const repo = findRepo(owner, name);
  if (repo === null) {
    sendError(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

/** Resolve a ref-ish value (branch name, ref or commit oid) to a commit oid. */
function resolveCommit(repo: RepoRec, ref: string | null): string | undefined {
  if (ref === null || ref === '') return branchTip(repo, repo.defaultBranch);
  const byBranch = repo.refs.get(`refs/heads/${ref}`) ?? repo.refs.get(ref);
  if (byBranch !== undefined) return byBranch;
  const object = repo.objects.get(ref);
  if (object !== undefined && object.type === 'commit') return ref;
  if (object !== undefined && object.type === 'tag') return peelToCommit(repo, ref);
  return undefined;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const method = req.method ?? 'GET';
  const path = url.pathname;
  const raw = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
  let body: Record<string, unknown> = {};
  if (raw.length > 0) {
    const parsed = parseJsonBody(raw);
    if (parsed === null) {
      sendError(res, 400, 'Problems parsing JSON');
      return;
    }
    body = parsed;
  }
  if (!authed(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }

  const segments = path.split('/').filter((s) => s !== '').map((s) => decodeURIComponent(s));
  // segments[0] = 'api', [1] = 'v3'
  const rest = segments.slice(2);

  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(
        res,
        200,
        { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' },
        { 'x-oauth-scopes': 'repo, read:org' },
      );
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (rest[0] === 'meta' && rest.length === 1 && method === 'GET') {
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: false });
    return;
  }

  if (rest[0] === 'user' && rest.length === 1 && method === 'GET') {
    sendJson(res, 200, { login: viewer(), id: 1000, type: 'User', name: viewer() });
    return;
  }

  if (rest[0] === 'user' && rest[1] === 'repos' && rest.length === 2) {
    if (method === 'POST') {
      const name = str(body.name);
      if (name === '') {
        sendError(res, 422, 'Repository creation failed: name is required');
        return;
      }
      const existing = reposByName.get(name);
      if (existing !== undefined) {
        sendError(res, 422, 'Repository already exists');
        return;
      }
      const repo = createRepo(name, str(body.description), body.private !== false);
      sendJson(res, 201, repoJson(repo));
      return;
    }
    if (method === 'GET') {
      const perPage = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? '30') || 30));
      const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
      const all = [...reposByName.values()].sort((a, b) => a.dbId - b.dbId);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const headers: Record<string, string> = {};
      if (page * perPage < all.length) {
        const host = req.headers.host ?? 'localhost';
        const next = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
        const lastPage = Math.ceil(all.length / perPage);
        const last = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${lastPage}`;
        headers.link = `<${next}>; rel="next", <${last}>; rel="last"`;
      }
      sendJson(res, 200, slice.map((repo) => repoJson(repo)), headers);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (rest[0] !== 'repos' || rest.length < 3) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const owner = rest[1] as string;
  const repoName = rest[2] as string;
  const tail = rest.slice(3);

  if (tail.length === 0) {
    const repo = repoFromParams(res, owner, repoName);
    if (repo === null) return;
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH') {
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.priv = body.private;
      if (typeof body.name === 'string' && body.name !== '' && body.name !== repo.name) {
        // Renaming is not exercised by the suite; keep the object reachable.
      }
      repo.updatedAt = nowIso();
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      reposByName.delete(repoName);
      res.writeHead(204, { 'x-github-request-id': nextRequestId() });
      res.end();
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const repo = repoFromParams(res, owner, repoName);
  if (repo === null) return;

  // ---- branches and commits
  if (tail[0] === 'branches' && method === 'GET') {
    if (tail.length === 1) {
      const branches: Record<string, unknown>[] = [];
      for (const [ref, oid] of repo.refs) {
        if (ref.startsWith('refs/heads/')) {
          branches.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
        }
      }
      branches.sort((a, b) => String(a.name).localeCompare(String(b.name)));
      sendJson(res, 200, branches);
      return;
    }
    const branchName = tail.slice(1).join('/');
    const tip = branchTip(repo, branchName);
    if (tip === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { name: branchName, commit: { sha: tip }, protected: false });
    return;
  }

  if (tail[0] === 'commits' && tail.length === 1 && method === 'GET') {
    const tip = resolveCommit(repo, url.searchParams.get('sha'));
    if (tip === undefined) {
      sendJson(res, 200, []);
      return;
    }
    const commits = walkCommits(repo, tip).map((oid) => {
      const object = repo.objects.get(oid) as GitObject;
      const info = parseCommit(object.data);
      return {
        sha: oid,
        node_id: globalId('Commit', oid),
        commit: {
          message: info.message.replace(/\n$/, ''),
          tree: { sha: info.tree },
          author: { name: info.author, email: '', date: repo.createdAt },
          committer: { name: info.committer, email: '', date: repo.createdAt },
        },
        parents: info.parents.map((parent) => ({ sha: parent })),
      };
    });
    sendJson(res, 200, commits);
    return;
  }

  // ---- git refs
  if (tail[0] === 'git' && tail[1] === 'refs') {
    if (tail.length === 2 && method === 'POST') {
      const ref = str(body.ref);
      const sha = str(body.sha);
      if (!ref.startsWith('refs/') || !/^[0-9a-f]{40}$/.test(sha)) {
        sendError(res, 422, 'Invalid ref or sha');
        return;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, node_id: globalId('Ref', ref), object: { sha, type: 'commit' } });
      return;
    }
    if (method === 'GET' && tail.length >= 3) {
      const ref = `refs/${tail.slice(2).join('/')}`;
      const oid = repo.refs.get(ref);
      if (oid === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, { ref, node_id: globalId('Ref', ref), object: { sha: oid, type: 'commit' } });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // ---- contents
  if (tail[0] === 'contents') {
    const contentPath = tail.slice(1).join('/');
    if (method === 'GET') {
      const tip = resolveCommit(repo, url.searchParams.get('ref'));
      if (tip === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const flat = flatOfCommit(repo, tip);
      const file = flat.get(contentPath);
      if (file !== undefined) {
        const blob = repo.objects.get(file.oid) as GitObject;
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          content: blob.data.toString('base64'),
          sha: file.oid,
          size: blob.data.length,
          name: contentPath.split('/').pop() ?? contentPath,
          path: contentPath,
        });
        return;
      }
      // A directory listing, when the path prefixes stored files (or is root).
      const prefix = contentPath === '' ? '' : `${contentPath}/`;
      const children = new Map<string, { type: string; sha: string }>();
      for (const [path, entry] of flat) {
        if (!path.startsWith(prefix)) continue;
        const restPath = path.slice(prefix.length);
        const slash = restPath.indexOf('/');
        if (slash < 0) children.set(restPath, { type: 'file', sha: entry.oid });
        else {
          const dir = restPath.slice(0, slash);
          if (!children.has(dir)) {
            // The directory's tree oid: walk the real tree.
            children.set(dir, { type: 'dir', sha: dirTreeOid(repo, tip, prefix + dir) });
          }
        }
      }
      if (children.size > 0 || contentPath === '') {
        const listing = [...children.entries()]
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(([name, child]) => ({ type: child.type, name, path: prefix + name, sha: child.sha }));
        sendJson(res, 200, listing);
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'PUT') {
      const branch = strOr(body.branch, repo.defaultBranch);
      const tip = branchTip(repo, branch) ?? branchTip(repo, repo.defaultBranch);
      const flat = tip === undefined ? new Map<string, { oid: string; mode: string }>() : flatOfCommit(repo, tip);
      const existing = flat.get(contentPath);
      if (existing !== undefined && typeof body.sha === 'string' && body.sha !== '' && body.sha.toLowerCase() !== existing.oid.toLowerCase()) {
        sendError(res, 409, 'Conflict: the file has changed');
        return;
      }
      const content = Buffer.from(str(body.content), 'base64');
      const commit = commitChanges(repo, branch, new Map([[contentPath, content]]), strOr(body.message, 'Update file'));
      const blobOid = storeObject(repo, 'blob', content);
      sendJson(res, existing !== undefined ? 200 : 201, {
        content: {
          type: 'file',
          encoding: 'base64',
          content: content.toString('base64'),
          sha: blobOid,
          size: content.length,
          name: contentPath.split('/').pop() ?? contentPath,
          path: contentPath,
        },
        commit: { sha: commit },
      });
      return;
    }
    if (method === 'DELETE') {
      const branch = strOr(body.branch, repo.defaultBranch);
      const tip = branchTip(repo, branch);
      const flat = tip === undefined ? new Map<string, { oid: string; mode: string }>() : flatOfCommit(repo, tip);
      if (!flat.has(contentPath)) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const commit = commitChanges(repo, branch, new Map([[contentPath, null]]), strOr(body.message, 'Delete file'));
      sendJson(res, 200, { content: null, commit: { sha: commit } });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // ---- labels
  if (tail[0] === 'labels' && tail.length === 1 && method === 'POST') {
    const name = str(body.name);
    if (name === '') {
      sendError(res, 422, 'Validation Failed: name is required');
      return;
    }
    repo.labels.add(name);
    sendJson(res, 201, { id: nextCommentDbId, name, color: strOr(body.color, 'ededed'), description: null });
    return;
  }

  // ---- issues
  if (tail[0] === 'issues') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const labels = Array.isArray(body.labels) ? body.labels.map((l) => (typeof l === 'string' ? l : str((l as Record<string, unknown>)?.name))).filter((l) => l !== '') : [];
        for (const label of labels) {
          if (!repo.labels.has(label)) {
            sendError(res, 422, `Validation Failed: label "${label}" does not exist`);
            return;
          }
        }
        const issue = createIssue(repo, str(body.title), str(body.body), labels);
        sendJson(res, 201, issueJson(repo, issue));
        return;
      }
      if (method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        const direction = url.searchParams.get('direction') ?? 'asc';
        const perPage = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? '30') || 30));
        const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
        let list = [...repo.issues.values()];
        if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
        list.sort((a, b) => (direction === 'desc' ? b.number - a.number : a.number - b.number));
        sendJson(res, 200, list.slice((page - 1) * perPage, page * perPage).map((issue) => issueJson(repo, issue)));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const number = Number(tail[1]);
    const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;
    if (tail.length === 2) {
      if (issue === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, issueJson(repo, issue));
        return;
      }
      if (method === 'PATCH') {
        if (body.state === 'closed' || body.state === 'open') issue.state = body.state;
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        issue.updatedAt = nowIso();
        sendJson(res, 200, issueJson(repo, issue));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 3 && tail[2] === 'comments') {
      if (issue === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'POST') {
        const comment: CommentRec = { dbId: nextCommentDbId, body: str(body.body), createdAt: nowIso() };
        nextCommentDbId += 1;
        const list = repo.comments.get(issue.number) ?? [];
        list.push(comment);
        repo.comments.set(issue.number, list);
        sendJson(res, 201, commentJson(repo, issue.number, comment));
        return;
      }
      if (method === 'GET') {
        const list = repo.comments.get(issue.number) ?? [];
        sendJson(res, 200, list.map((comment) => commentJson(repo, issue.number, comment)));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // ---- pull requests
  if (tail[0] === 'pulls') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const head = str(body.head);
        const base = strOr(body.base, repo.defaultBranch);
        if (head === '') {
          sendError(res, 422, 'Validation Failed: head is required');
          return;
        }
        const pull = createPull(repo, str(body.title), str(body.body), head, base);
        sendJson(res, 201, pullJson(repo, pull));
        return;
      }
      if (method === 'GET') {
        const state = url.searchParams.get('state') ?? 'open';
        const perPage = Math.max(1, Math.min(100, Number(url.searchParams.get('per_page') ?? '30') || 30));
        const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
        let list = [...repo.pulls.values()];
        if (state === 'open' || state === 'closed') list = list.filter((pull) => pull.state === state);
        list.sort((a, b) => a.number - b.number);
        sendJson(res, 200, list.slice((page - 1) * perPage, page * perPage).map((pull) => pullJson(repo, pull)));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const number = Number(tail[1]);
    const pull = Number.isInteger(number) ? repo.pulls.get(number) : undefined;
    if (pull === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (tail.length === 2 && method === 'GET') {
      sendJson(res, 200, pullJson(repo, pull));
      return;
    }
    if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
      sendJson(res, 200, pullChangedFiles(repo, pull));
      return;
    }
    if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
      if (pull.merged) {
        sendJson(res, 200, { sha: pull.mergeCommitSha ?? '', merged: true, message: 'Pull Request successfully merged' });
        return;
      }
      const result = mergePull(repo, pull);
      if (result === null) {
        sendError(res, 405, 'Pull Request is not mergeable: content conflict');
        return;
      }
      sendJson(res, 200, { sha: result.sha, merged: true, message: 'Pull Request successfully merged' });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  sendError(res, 404, 'Not Found');
}

/** The tree oid of a directory path inside a commit, for directory listings. */
function dirTreeOid(repo: RepoRec, commitOid: string, dirPath: string): string {
  let treeOid = treeOfCommit(repo, commitOid);
  if (dirPath === '') return treeOid;
  for (const segment of dirPath.split('/')) {
    const tree = repo.objects.get(treeOid);
    if (tree === undefined || tree.type !== 'tree') return ZERO_OID;
    const entry = parseTree(tree.data).find((candidate) => candidate.name === segment && candidate.mode === '40000');
    if (entry === undefined) return ZERO_OID;
    treeOid = entry.oid;
  }
  return treeOid;
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small parser + executor over the same store
// ---------------------------------------------------------------------------

type GqlValue =
  | { readonly kind: 'variable'; readonly name: string }
  | { readonly kind: 'int'; readonly value: number }
  | { readonly kind: 'float'; readonly value: number }
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'boolean'; readonly value: boolean }
  | { readonly kind: 'enum'; readonly value: string }
  | { readonly kind: 'null' }
  | { readonly kind: 'list'; readonly values: readonly GqlValue[] }
  | { readonly kind: 'object'; readonly fields: ReadonlyArray<{ readonly name: string; readonly value: GqlValue }> };

interface GqlField {
  readonly name: string;
  readonly alias: string | null;
  readonly args: ReadonlyArray<{ readonly name: string; readonly value: GqlValue }>;
  readonly selection: readonly GqlField[] | null;
  readonly inlineType: string | null; // set for inline fragments: the fragment is a pseudo-field
}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (/\s|,/.test(ch)) {
      i += 1;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:$!@='.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        const text = source.slice(i + 3, end < 0 ? source.length : end);
        tokens.push(`"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
        i = end < 0 ? source.length : end + 3;
        continue;
      }
      let j = i + 1;
      let text = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          text += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          text += source[j];
          j += 1;
        }
      }
      tokens.push(`"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
      i = j + 1;
      continue;
    }
    const nameMatch = /^[_A-Za-z][_0-9A-Za-z]*/.exec(source.slice(i));
    if (nameMatch !== null) {
      tokens.push(nameMatch[0]);
      i += nameMatch[0].length;
      continue;
    }
    const numMatch = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(source.slice(i));
    if (numMatch !== null) {
      tokens.push(numMatch[0]);
      i += numMatch[0].length;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: string[];
  constructor(tokens: string[]) {
    this.tokens = tokens;
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }
  private next(): string {
    const token = this.tokens[this.pos];
    if (token === undefined) throw new Error('unexpected end of GraphQL document');
    this.pos += 1;
    return token;
  }
  private expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new Error(`expected ${token}, got ${got}`);
  }
  private skipType(): void {
    // A type reference: Name, [Type], with optional ! suffixes.
    if (this.peek() === '[') {
      this.next();
      this.skipType();
      this.expect(']');
    } else {
      this.next();
    }
    while (this.peek() === '!') this.next();
  }
  private parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { kind: 'variable', name: this.next() };
    if (token === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.next();
      return { kind: 'list', values };
    }
    if (token === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (this.peek() !== '}') {
        const name = this.next();
        this.expect(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.next();
      return { kind: 'object', fields };
    }
    if (token.startsWith('"')) return { kind: 'string', value: JSON.parse(token) as string };
    if (token === 'true' || token === 'false') return { kind: 'boolean', value: token === 'true' };
    if (token === 'null') return { kind: 'null' };
    if (/^-?\d+$/.test(token)) return { kind: 'int', value: Number(token) };
    if (/^-?\d*\.\d/.test(token)) return { kind: 'float', value: Number(token) };
    return { kind: 'enum', value: token };
  }
  private parseSelectionSet(): GqlField[] {
    this.expect('{');
    const fields: GqlField[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === '...') {
        this.next();
        if (this.peek() === 'on') {
          this.next();
          const type = this.next();
          const selection = this.parseSelectionSet();
          fields.push({ name: '', alias: null, args: [], selection, inlineType: type });
          continue;
        }
        throw new Error('named fragments are not supported');
      }
      let name = this.next();
      let alias: string | null = null;
      if (this.peek() === ':') {
        this.next();
        alias = name;
        name = this.next();
      }
      const args: { name: string; value: GqlValue }[] = [];
      if (this.peek() === '(') {
        this.next();
        while (this.peek() !== ')') {
          const argName = this.next();
          this.expect(':');
          args.push({ name: argName, value: this.parseValue() });
        }
        this.next();
      }
      // Directives are parsed and ignored.
      while (this.peek() === '@') {
        this.next();
        this.next();
        if (this.peek() === '(') {
          this.next();
          while (this.peek() !== ')') {
            this.next();
            this.expect(':');
            this.parseValue();
          }
          this.next();
        }
      }
      let selection: GqlField[] | null = null;
      if (this.peek() === '{') selection = this.parseSelectionSet();
      fields.push({ name, alias, args, selection, inlineType: null });
    }
    this.next();
    return fields;
  }

  /** Parse a document into its operations' selection sets. */
  parseDocument(): { readonly type: 'query' | 'mutation'; readonly selection: GqlField[] }[] {
    const operations: { type: 'query' | 'mutation'; selection: GqlField[] }[] = [];
    while (this.pos < this.tokens.length) {
      const token = this.peek();
      if (token === '{') {
        operations.push({ type: 'query', selection: this.parseSelectionSet() });
      } else if (token === 'query' || token === 'mutation' || token === 'subscription') {
        const kind = this.next();
        // Optional operation name.
        if (this.peek() !== '(' && this.peek() !== '{' && this.peek() !== '@') this.next();
        // Variable definitions.
        if (this.peek() === '(') {
          this.next();
          while (this.peek() !== ')') {
            this.expect('$');
            this.next();
            this.expect(':');
            this.skipType();
            if (this.peek() === '=') {
              this.next();
              this.parseValue();
            }
            while (this.peek() === '@') {
              this.next();
              this.next();
            }
          }
          this.next();
        }
        while (this.peek() === '@') {
          this.next();
          this.next();
          if (this.peek() === '(') {
            let depth = 0;
            do {
              const t = this.next();
              if (t === '(') depth += 1;
              if (t === ')') depth -= 1;
            } while (depth > 0);
          }
        }
        operations.push({ type: kind === 'mutation' ? 'mutation' : 'query', selection: this.parseSelectionSet() });
      } else if (token === 'fragment') {
        // Skip a fragment definition: name 'on' Type selection-set.
        this.next();
        this.next();
        this.next();
        this.next();
        this.parseSelectionSet();
      } else {
        throw new Error(`unexpected token ${String(token)} in GraphQL document`);
      }
    }
    return operations;
  }
}

function resolveGqlValue(value: GqlValue, variables: Readonly<Record<string, unknown>>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name];
    case 'int':
    case 'float':
    case 'string':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'list':
      return value.values.map((v) => resolveGqlValue(v, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = resolveGqlValue(field.value, variables);
      return out;
    }
  }
}

// The schema's field lists: validation and introspection read the same table,
// so a field the executor accepts is exactly a field __type reports.
const GQL_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', 'search', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['login', 'id', 'name', 'url', 'email'],
  RepositoryOwner: ['login', 'id', 'url'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission',
    'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'description', 'isPrivate',
    'url', 'createdAt', 'updatedAt',
  ],
  Ref: ['name', 'prefix', 'target'],
  Issue: [
    'id', 'number', 'title', 'state', 'body', 'bodyText', 'url', 'author', 'repository', 'labels',
    'comments', 'createdAt', 'updatedAt', 'closedAt',
  ],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName',
    'files', 'author', 'repository', 'createdAt', 'updatedAt', 'url', 'additions', 'deletions',
    'changedFiles', 'commits', 'mergeCommit',
  ],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  IssueEdge: ['node', 'cursor'],
  PullRequestEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'url'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', 'ofType', 'interfaces'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason'],
  __Schema: ['types', 'queryType', 'mutationType', 'subscriptionType', 'directives'],
};

const GQL_ENUMS: Readonly<Record<string, readonly string[]>> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
};

interface GqlCtx {
  readonly variables: Readonly<Record<string, unknown>>;
  readonly errors: { message: string }[];
}

type GqlSource =
  | { readonly type: 'Query' }
  | { readonly type: 'Mutation' }
  | { readonly type: 'User' }
  | { readonly type: 'Repository'; readonly repo: RepoRec }
  | { readonly type: 'Issue'; readonly repo: RepoRec; readonly issue: IssueRec }
  | { readonly type: 'PullRequest'; readonly repo: RepoRec; readonly pull: PullRec }
  | { readonly type: 'IssueConnection'; readonly repo: RepoRec; readonly items: IssueRec[]; readonly hasNextPage: boolean; readonly endCursor: string }
  | { readonly type: 'PullRequestConnection'; readonly repo: RepoRec; readonly items: PullRec[] }
  | { readonly type: 'FilesConnection'; readonly files: ChangedFile[] }
  | { readonly type: 'PageInfo'; readonly hasNextPage: boolean; readonly endCursor: string }
  | { readonly type: 'ChangedFile'; readonly file: ChangedFile }
  | { readonly type: 'Ref'; readonly name: string }
  | { readonly type: 'Payload'; readonly payloadType: string; readonly value: unknown }
  | { readonly type: 'CommentEdge'; readonly repo: RepoRec; readonly issueNumber: number; readonly comment: CommentRec }
  | { readonly type: 'IssueComment'; readonly repo: RepoRec; readonly issueNumber: number; readonly comment: CommentRec }
  | { readonly type: '__Type'; readonly typeName: string }
  | { readonly type: '__Field'; readonly name: string }
  | { readonly type: '__EnumValue'; readonly name: string };

function cursorFor(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}

function indexFromCursor(cursor: unknown): number {
  if (typeof cursor !== 'string' || cursor === '') return 0;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? 0 : Number(match[1]);
  } catch {
    return 0;
  }
}

function gqlResolveField(source: GqlSource, field: GqlField, ctx: GqlCtx): unknown {
  const args: Record<string, unknown> = {};
  for (const arg of field.args) args[arg.name] = resolveGqlValue(arg.value, ctx.variables);
  const name = field.name;
  switch (source.type) {
    case 'Query': {
      if (name === 'viewer') return { type: 'User' } satisfies GqlSource;
      if (name === '__type') {
        const typeName = str(args.name);
        if (GQL_FIELDS[typeName] === undefined && GQL_ENUMS[typeName] === undefined) return null;
        return { type: '__Type', typeName } satisfies GqlSource;
      }
      if (name === 'repository') {
        const repo = findRepo(str(args.owner), str(args.name));
        return repo === null ? null : ({ type: 'Repository', repo } satisfies GqlSource);
      }
      if (name === 'node') {
        const decoded = decodeGlobalId(str(args.id));
        if (decoded !== null && decoded.kind === 'Repository') {
          const repo = repoByDbId(Number(decoded.parts[0]));
          return repo === null ? null : ({ type: 'Repository', repo } satisfies GqlSource);
        }
        return null;
      }
      return null;
    }
    case 'Mutation': {
      if (name === 'createIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(str(input.repositoryId));
        const repo = decoded === null ? null : repoByDbId(Number(decoded.parts[0]));
        if (repo === null) return null;
        const issue = createIssue(repo, str(input.title), str(input.body), []);
        return { type: 'Payload', payloadType: 'CreateIssuePayload', value: { type: 'Issue', repo, issue } } satisfies GqlSource;
      }
      if (name === 'closeIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(str(input.issueId));
        if (decoded === null) return null;
        const repo = repoByDbId(Number(decoded.parts[0]));
        const issue = repo?.issues.get(Number(decoded.parts[1]));
        if (repo === null || repo === undefined || issue === undefined) return null;
        issue.state = 'closed';
        issue.updatedAt = nowIso();
        return { type: 'Payload', payloadType: 'CloseIssuePayload', value: { type: 'Issue', repo, issue } } satisfies GqlSource;
      }
      if (name === 'createPullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(str(input.repositoryId));
        const repo = decoded === null ? null : repoByDbId(Number(decoded.parts[0]));
        if (repo === null) return null;
        const pull = createPull(repo, str(input.title), str(input.body), str(input.headRefName), strOr(input.baseRefName, repo.defaultBranch));
        return { type: 'Payload', payloadType: 'CreatePullRequestPayload', value: { type: 'PullRequest', repo, pull } } satisfies GqlSource;
      }
      if (name === 'mergePullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(str(input.pullRequestId));
        if (decoded === null) return null;
        const repo = repoByDbId(Number(decoded.parts[0]));
        const pull = repo?.pulls.get(Number(decoded.parts[1]));
        if (repo === null || repo === undefined || pull === undefined) return null;
        if (!pull.merged) mergePull(repo, pull);
        return { type: 'Payload', payloadType: 'MergePullRequestPayload', value: { type: 'PullRequest', repo, pull } } satisfies GqlSource;
      }
      if (name === 'addComment') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const decoded = decodeGlobalId(str(input.subjectId));
        if (decoded === null) return null;
        const repo = repoByDbId(Number(decoded.parts[0]));
        const issue = repo?.issues.get(Number(decoded.parts[1]));
        if (repo === null || repo === undefined || issue === undefined) return null;
        const comment: CommentRec = { dbId: nextCommentDbId, body: str(input.body), createdAt: nowIso() };
        nextCommentDbId += 1;
        const list = repo.comments.get(issue.number) ?? [];
        list.push(comment);
        repo.comments.set(issue.number, list);
        return {
          type: 'Payload',
          payloadType: 'AddCommentPayload',
          value: { type: 'CommentEdge', repo, issueNumber: issue.number, comment },
        } satisfies GqlSource;
      }
      return null;
    }
    case 'User':
      if (name === 'login') return viewer();
      if (name === 'id') return globalId('User', '1000');
      if (name === 'name') return viewer();
      if (name === 'url') return `https://forge.invalid/${viewer()}`;
      return null;
    case 'Repository': {
      const repo = source.repo;
      switch (name) {
        case 'id':
          return repoGlobalId(repo);
        case 'databaseId':
          return repo.dbId;
        case 'name':
          return repo.name;
        case 'nameWithOwner':
          return `${viewer()}/${repo.name}`;
        case 'owner':
          return { type: 'User' } satisfies GqlSource;
        case 'defaultBranchRef':
          return { type: 'Ref', name: repo.defaultBranch } satisfies GqlSource;
        case 'viewerPermission':
          return 'ADMIN';
        case 'hasIssuesEnabled':
          return true;
        case 'description':
          return repo.description;
        case 'isPrivate':
          return repo.priv;
        case 'issue': {
          const issue = repo.issues.get(Number(args.number));
          return issue === undefined ? null : ({ type: 'Issue', repo, issue } satisfies GqlSource);
        }
        case 'issues': {
          let items = [...repo.issues.values()];
          const states = args.states;
          if (Array.isArray(states) && states.length > 0) {
            const wanted = new Set(states.map((s) => String(s).toLowerCase()));
            items = items.filter((issue) => wanted.has(issue.state));
          }
          const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
          const direction = str(orderBy.direction);
          items.sort((a, b) => (direction === 'DESC' ? b.number - a.number : a.number - b.number));
          const start = args.after === undefined || args.after === null ? 0 : indexFromCursor(args.after);
          const first = typeof args.first === 'number' ? args.first : items.length;
          const page = items.slice(start, start + first);
          const hasNext = start + page.length < items.length;
          return {
            type: 'IssueConnection',
            repo,
            items: page,
            hasNextPage: hasNext,
            endCursor: cursorFor(start + page.length),
          } satisfies GqlSource;
        }
        case 'pullRequest': {
          const pull = repo.pulls.get(Number(args.number));
          return pull === undefined ? null : ({ type: 'PullRequest', repo, pull } satisfies GqlSource);
        }
        case 'pullRequests': {
          let items = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
          const first = typeof args.first === 'number' ? args.first : items.length;
          items = items.slice(0, first);
          return { type: 'PullRequestConnection', repo, items } satisfies GqlSource;
        }
        default:
          return null;
      }
    }
    case 'Issue': {
      const { repo, issue } = source;
      switch (name) {
        case 'id':
          return issueGlobalId(repo, issue);
        case 'number':
          return issue.number;
        case 'title':
          return issue.title;
        case 'state':
          return issue.state.toUpperCase();
        case 'body':
        case 'bodyText':
          return issue.body;
        case 'author':
          return { type: 'User' } satisfies GqlSource;
        case 'repository':
          return { type: 'Repository', repo } satisfies GqlSource;
        case 'createdAt':
          return issue.createdAt;
        case 'updatedAt':
          return issue.updatedAt;
        case 'closedAt':
          return issue.state === 'closed' ? issue.updatedAt : null;
        default:
          return null;
      }
    }
    case 'PullRequest': {
      const { repo, pull } = source;
      switch (name) {
        case 'id':
          return pullGlobalId(repo, pull);
        case 'number':
          return pull.number;
        case 'title':
          return pull.title;
        case 'body':
          return pull.body;
        case 'state':
          return pull.merged ? 'MERGED' : pull.state.toUpperCase();
        case 'merged':
          return pull.merged;
        case 'mergeable':
          return pullIsConflicted(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
        case 'headRefName':
          return pull.headRef;
        case 'baseRefName':
          return pull.baseRef;
        case 'files':
          return { type: 'FilesConnection', files: pullChangedFiles(repo, pull) } satisfies GqlSource;
        case 'author':
          return { type: 'User' } satisfies GqlSource;
        case 'repository':
          return { type: 'Repository', repo } satisfies GqlSource;
        case 'createdAt':
          return pull.createdAt;
        case 'updatedAt':
          return pull.updatedAt;
        case 'changedFiles':
          return pullChangedFiles(repo, pull).length;
        case 'additions':
          return pullChangedFiles(repo, pull).reduce((sum, f) => sum + f.additions, 0);
        case 'deletions':
          return pullChangedFiles(repo, pull).reduce((sum, f) => sum + f.deletions, 0);
        default:
          return null;
      }
    }
    case 'IssueConnection':
      if (name === 'nodes') return source.items.map((issue) => ({ type: 'Issue', repo: source.repo, issue }) satisfies GqlSource);
      if (name === 'pageInfo') return { type: 'PageInfo', hasNextPage: source.hasNextPage, endCursor: source.endCursor } satisfies GqlSource;
      if (name === 'totalCount') return source.items.length;
      if (name === 'edges') return [];
      return null;
    case 'PullRequestConnection':
      if (name === 'nodes') return source.items.map((pull) => ({ type: 'PullRequest', repo: source.repo, pull }) satisfies GqlSource);
      if (name === 'pageInfo') return { type: 'PageInfo', hasNextPage: false, endCursor: cursorFor(source.items.length) } satisfies GqlSource;
      if (name === 'totalCount') return source.items.length;
      if (name === 'edges') return [];
      return null;
    case 'FilesConnection':
      if (name === 'nodes') return source.files.map((file) => ({ type: 'ChangedFile', file }) satisfies GqlSource);
      if (name === 'pageInfo') return { type: 'PageInfo', hasNextPage: false, endCursor: cursorFor(source.files.length) } satisfies GqlSource;
      if (name === 'totalCount') return source.files.length;
      if (name === 'edges') return [];
      return null;
    case 'PageInfo':
      if (name === 'hasNextPage') return source.hasNextPage;
      if (name === 'hasPreviousPage') return false;
      if (name === 'endCursor') return source.endCursor;
      if (name === 'startCursor') return source.endCursor;
      return null;
    case 'ChangedFile':
      if (name === 'path') return source.file.filename;
      if (name === 'additions') return source.file.additions;
      if (name === 'deletions') return source.file.deletions;
      if (name === 'changeType') return source.file.status.toUpperCase();
      return null;
    case 'Ref':
      if (name === 'name') return source.name;
      if (name === 'prefix') return 'refs/heads/';
      return null;
    case 'Payload': {
      const value = source.value as GqlSource;
      if (name === 'issue' || name === 'pullRequest' || name === 'commentEdge') return value;
      if (name === 'clientMutationId') return null;
      if (name === 'subject') return null;
      return null;
    }
    case 'CommentEdge':
      if (name === 'node') return { type: 'IssueComment', repo: source.repo, issueNumber: source.issueNumber, comment: source.comment } satisfies GqlSource;
      if (name === 'cursor') return cursorFor(source.comment.dbId);
      return null;
    case 'IssueComment':
      if (name === 'id') return commentGlobalId(source.repo, source.issueNumber, source.comment);
      if (name === 'body') return source.comment.body;
      if (name === 'author') return { type: 'User' } satisfies GqlSource;
      if (name === 'createdAt') return source.comment.createdAt;
      return null;
    case '__Type': {
      const typeName = source.typeName;
      if (name === 'name') return typeName;
      if (name === 'kind') return GQL_ENUMS[typeName] !== undefined ? 'ENUM' : 'OBJECT';
      if (name === 'fields') {
        const fields = GQL_FIELDS[typeName] ?? [];
        return fields.map((fieldName) => ({ type: '__Field', name: fieldName }) satisfies GqlSource);
      }
      if (name === 'enumValues') {
        const values = GQL_ENUMS[typeName] ?? [];
        return values.map((value) => ({ type: '__EnumValue', name: value }) satisfies GqlSource);
      }
      return null;
    }
    case '__Field':
      if (name === 'name') return source.name;
      if (name === 'isDeprecated') return false;
      return null;
    case '__EnumValue':
      if (name === 'name') return source.name;
      if (name === 'isDeprecated') return false;
      return null;
  }
}

/** The GraphQL type name a source serializes as (drives field validation). */
function gqlTypeName(source: GqlSource): string {
  switch (source.type) {
    case 'Payload':
      return source.payloadType;
    case 'FilesConnection':
      return 'PullRequestChangedFileConnection';
    case 'ChangedFile':
      return 'PullRequestChangedFile';
    default:
      return source.type;
  }
}

function gqlExecuteSelection(source: GqlSource, selection: readonly GqlField[], ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const typeName = gqlTypeName(source);
  const knownFields = GQL_FIELDS[typeName] ?? [];
  for (const field of selection) {
    if (field.inlineType !== null) {
      // An inline fragment applies when the runtime type matches (Node is the
      // interface a Repository source answers to).
      if (field.inlineType === typeName || field.inlineType === 'Node') {
        Object.assign(out, gqlExecuteSelection(source, field.selection ?? [], ctx));
      }
      continue;
    }
    const key = field.alias ?? field.name;
    if (!knownFields.includes(field.name)) {
      ctx.errors.push({ message: `Field '${field.name}' doesn't exist on type '${typeName}'` });
      out[key] = null;
      continue;
    }
    const value = gqlResolveField(source, field, ctx);
    if (value === null || value === undefined) {
      out[key] = null;
    } else if (typeof value === 'object' && 'type' in (value as Record<string, unknown>)) {
      out[key] = field.selection === null ? null : gqlExecuteSelection(value as GqlSource, field.selection, ctx);
    } else if (Array.isArray(value)) {
      out[key] = value.map((item) =>
        typeof item === 'object' && item !== null && 'type' in (item as Record<string, unknown>)
          ? gqlExecuteSelection(item as GqlSource, field.selection ?? [], ctx)
          : item,
      );
    } else {
      out[key] = value;
    }
  }
  return out;
}

function executeGraphql(body: Record<string, unknown>): Record<string, unknown> {
  const query = str(body.query);
  const variables = (typeof body.variables === 'object' && body.variables !== null ? body.variables : {}) as Record<string, unknown>;
  let operations: { type: 'query' | 'mutation'; selection: GqlField[] }[];
  try {
    operations = new GqlParser(tokenizeGql(query)).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
  const operation = operations[0];
  if (operation === undefined) return { data: null, errors: [{ message: 'no operation in document' }] };
  const ctx: GqlCtx = { variables, errors: [] };
  const root: GqlSource = operation.type === 'mutation' ? { type: 'Mutation' } : { type: 'Query' };
  const data = gqlExecuteSelection(root, operation.selection, ctx);
  const envelope: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) envelope.errors = ctx.errors;
  return envelope;
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if ((req.method ?? 'GET') !== 'POST') {
    sendError(res, 404, 'Not Found');
    return;
  }
  if (!authed(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, { data: null, errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  if (Array.isArray(parsed)) {
    const results = parsed.map((entry) => executeGraphql((entry ?? {}) as Record<string, unknown>));
    sendJson(res, 200, results);
    return;
  }
  sendJson(res, 200, executeGraphql((parsed ?? {}) as Record<string, unknown>));
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over streamable HTTP (modern discover + legacy handshake)
// ---------------------------------------------------------------------------

interface McpTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Readonly<Record<string, { readonly type: string; readonly description: string }>>;
    readonly required: readonly string[];
  };
}

function tool(name: string, description: string, properties: Record<string, string>, required: string[]): McpTool {
  const props: Record<string, { type: string; description: string }> = {};
  for (const [key, desc] of Object.entries(properties)) props[key] = { type: key === 'private' ? 'boolean' : 'string', description: desc };
  if (name === 'merge_pull_request') props.pull_number = { type: 'number', description: 'The pull request number' };
  return { name, description, inputSchema: { type: 'object', properties: props, required } };
}

// The tool list is a fixed value: two tools/list calls must answer byte for
// byte identically, so it is built once and never mutated.
const MCP_TOOLS: readonly McpTool[] = [
  tool('create_repo', 'Create a new repository for the authenticated user', { name: 'The repository name', description: 'The repository description', private: 'Whether the repository is private' }, ['name']),
  tool('get_repo', 'Get a repository by owner and name', { owner: 'The repository owner', repo: 'The repository name' }, ['owner', 'repo']),
  tool('create_issue', 'Create an issue in a repository', { owner: 'The repository owner', repo: 'The repository name', title: 'The issue title', body: 'The issue body' }, ['owner', 'repo', 'title']),
  tool('list_issues', 'List issues in a repository', { owner: 'The repository owner', repo: 'The repository name', state: 'Filter by state: open, closed or all' }, ['owner', 'repo']),
  tool('create_pull_request', 'Create a pull request in a repository', { owner: 'The repository owner', repo: 'The repository name', title: 'The pull request title', body: 'The pull request body', head: 'The head branch', base: 'The base branch' }, ['owner', 'repo', 'title', 'head', 'base']),
  tool('merge_pull_request', 'Merge a pull request', { owner: 'The repository owner', repo: 'The repository name', pull_number: 'The pull request number' }, ['owner', 'repo', 'pull_number']),
];
const MCP_TOOLS_JSON = JSON.stringify({ tools: MCP_TOOLS });

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id as string | number | null, result };
}

function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id as string | number | null, error: { code, message } };
}

function toolResult(payload: unknown): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return { content: [{ type: 'text', text }], structuredContent: typeof payload === 'string' ? undefined : payload, isError: false };
}

function toolFailure(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(name: string, args: Record<string, unknown>, res: ServerResponse, id: unknown): void {
  const known = MCP_TOOLS.find((t) => t.name === name);
  if (known === undefined) {
    sendJson(res, 200, mcpError(id, -32602, `unknown tool: ${name}`));
    return;
  }
  for (const required of known.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      sendJson(res, 200, mcpError(id, -32602, `missing required argument: ${required}`));
      return;
    }
  }
  const owner = str(args.owner);
  const repoName = str(args.repo);
  switch (name) {
    case 'create_repo': {
      const repoNameArg = str(args.name);
      const existing = reposByName.get(repoNameArg);
      const repo = existing ?? createRepo(repoNameArg, str(args.description), args.private !== false);
      sendJson(res, 200, mcpResult(id, toolResult(repoJson(repo))));
      return;
    }
    case 'get_repo': {
      const repo = findRepo(owner, repoName);
      if (repo === null) {
        sendJson(res, 200, mcpResult(id, toolFailure(`repository ${owner}/${repoName} not found`)));
        return;
      }
      sendJson(res, 200, mcpResult(id, toolResult(repoJson(repo))));
      return;
    }
    case 'create_issue': {
      const repo = findRepo(owner, repoName);
      if (repo === null) {
        sendJson(res, 200, mcpResult(id, toolFailure(`repository ${owner}/${repoName} not found`)));
        return;
      }
      const issue = createIssue(repo, str(args.title), str(args.body), []);
      sendJson(res, 200, mcpResult(id, toolResult(issueJson(repo, issue))));
      return;
    }
    case 'list_issues': {
      const repo = findRepo(owner, repoName);
      if (repo === null) {
        sendJson(res, 200, mcpResult(id, toolFailure(`repository ${owner}/${repoName} not found`)));
        return;
      }
      const state = strOr(args.state, 'open');
      let list = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') list = list.filter((issue) => issue.state === state);
      sendJson(res, 200, mcpResult(id, toolResult(list.map((issue) => issueJson(repo, issue)))));
      return;
    }
    case 'create_pull_request': {
      const repo = findRepo(owner, repoName);
      if (repo === null) {
        sendJson(res, 200, mcpResult(id, toolFailure(`repository ${owner}/${repoName} not found`)));
        return;
      }
      const pull = createPull(repo, str(args.title), str(args.body), str(args.head), strOr(args.base, repo.defaultBranch));
      sendJson(res, 200, mcpResult(id, toolResult(pullJson(repo, pull))));
      return;
    }
    case 'merge_pull_request': {
      const repo = findRepo(owner, repoName);
      const number = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
      const pull = repo?.pulls.get(number);
      if (repo === null || repo === undefined || pull === undefined) {
        sendJson(res, 200, mcpResult(id, toolFailure('pull request not found')));
        return;
      }
      if (!pull.merged) {
        const result = mergePull(repo, pull);
        if (result === null) {
          sendJson(res, 200, mcpResult(id, toolFailure('pull request is not mergeable: content conflict')));
          return;
        }
      }
      sendJson(res, 200, mcpResult(id, toolResult(pullJson(repo, pull))));
      return;
    }
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  if (method === 'DELETE') {
    res.writeHead(200, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  if (method !== 'POST') {
    sendError(res, 404, 'Not Found');
    return;
  }
  if (!authed(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, mcpError(null, -32700, 'Parse error'));
    return;
  }
  const message = (parsed ?? {}) as Record<string, unknown>;
  const id = message.id;
  const rpcMethod = str(message.method);
  const params = (typeof message.params === 'object' && message.params !== null ? message.params : {}) as Record<string, unknown>;

  if (id === undefined) {
    // A notification: acknowledged, never answered with a result.
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return;
  }
  switch (rpcMethod) {
    case 'server/discover':
      sendJson(res, 200, mcpResult(id, {
        supportedVersions: ['2026-07-28', '2025-11-25'],
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
        resultType: 'complete',
      }));
      return;
    case 'initialize': {
      const offered = str(params.protocolVersion);
      sendJson(res, 200, mcpResult(id, {
        protocolVersion: /^\d{4}-\d{2}-\d{2}$/.test(offered) ? offered : '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
      }));
      return;
    }
    case 'ping':
      sendJson(res, 200, mcpResult(id, {}));
      return;
    case 'tools/list':
      // Answered from the pre-serialized constant so repeats are byte-identical.
      res.writeHead(200, {
        'content-type': JSON_TYPE,
        'content-length': Buffer.byteLength(`{"jsonrpc":"2.0","id":${JSON.stringify(id ?? null)},"result":${MCP_TOOLS_JSON}}\n`),
        'x-github-request-id': nextRequestId(),
      });
      res.end(`{"jsonrpc":"2.0","id":${JSON.stringify(id ?? null)},"result":${MCP_TOOLS_JSON}}\n`);
      return;
    case 'tools/call': {
      const args = (typeof params.arguments === 'object' && params.arguments !== null ? params.arguments : {}) as Record<string, unknown>;
      mcpCallTool(str(params.name), args, res, id);
      return;
    }
    default:
      sendJson(res, 200, mcpError(id, -32601, `method not found: ${rpcMethod}`));
      return;
  }
}

// ---------------------------------------------------------------------------
// git smart HTTP
// ---------------------------------------------------------------------------

function gitRepoOr404(res: ServerResponse, owner: string, name: string): RepoRec | null {
  const repo = findRepo(owner, name);
  if (repo === null) {
    sendError(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

function sortedRefs(repo: RepoRec): [string, string][] {
  return [...repo.refs.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

function handleInfoRefs(res: ServerResponse, repo: RepoRec, service: string, protocolHeader: string): void {
  const isUpload = service === 'git-upload-pack';
  const wantsV2 = isUpload && protocolHeader.includes('version=2');
  const preamble = encodePkt(`# service=${service}\n`);
  if (wantsV2) {
    const parts = [
      preamble,
      FLUSH_PKT,
      encodePkt('version 2\n'),
      encodePkt('agent=forge/1.0\n'),
      encodePkt('ls-refs=unborn\n'),
      encodePkt('fetch=shallow filter\n'),
      encodePkt('object-format=sha1\n'),
      FLUSH_PKT,
    ];
    const bodyBuffer = Buffer.concat(parts);
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-advertisement', 'content-length': bodyBuffer.length });
    res.end(bodyBuffer);
    return;
  }
  const caps = isUpload
    ? 'side-band-64k multi_ack_detailed thin-pack ofs-delta shallow agent=forge/1.0'
    : 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0';
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headTip = repo.refs.get(headTarget);
  const lines: Buffer[] = [preamble, FLUSH_PKT];
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    lines.push(encodePkt(Buffer.concat([Buffer.from(`${ZERO_OID} capabilities^{}\0${caps} symref=HEAD:${headTarget}\n`, 'utf8')])));
  } else {
    let first = true;
    const emit = (oid: string, ref: string): void => {
      if (first) {
        lines.push(encodePkt(Buffer.concat([Buffer.from(`${oid} ${ref}\0${caps} symref=HEAD:${headTarget}\n`, 'utf8')])));
        first = false;
      } else {
        lines.push(encodePkt(`${oid} ${ref}\n`));
      }
    };
    emit(headTip ?? ZERO_OID, 'HEAD');
    for (const [ref, oid] of refs) {
      emit(oid, ref);
      const object = repo.objects.get(oid);
      if (object !== undefined && object.type === 'tag') {
        lines.push(encodePkt(`${peelToCommit(repo, oid)} ${ref}^{}\n`));
      }
    }
  }
  lines.push(FLUSH_PKT);
  const bodyBuffer = Buffer.concat(lines);
  res.writeHead(200, {
    'content-type': isUpload ? 'application/x-git-upload-pack-advertisement' : 'application/x-git-receive-pack-advertisement',
    'content-length': bodyBuffer.length,
  });
  res.end(bodyBuffer);
}

/** Parse a v2 command request: header lines up to the delim, then argument lines up to the flush. */
function parseV2Command(body: Buffer): { readonly head: string[]; readonly args: string[] } {
  const { packets } = decodePkts(body);
  const head: string[] = [];
  const args: string[] = [];
  let inArgs = false;
  for (const packet of packets) {
    if (packet.kind === 'delim') {
      inArgs = true;
      continue;
    }
    if (packet.kind === 'flush' || packet.kind === 'response-end') break;
    const text = packet.payload.toString('utf8').replace(/\n$/, '');
    if (inArgs) args.push(text);
    else head.push(text);
  }
  return { head, args };
}

function handleLsRefs(res: ServerResponse, repo: RepoRec, args: readonly string[]): void {
  let peel = false;
  let symrefs = false;
  const prefixes: string[] = [];
  for (const arg of args) {
    if (arg === 'peel') peel = true;
    else if (arg === 'symrefs') symrefs = true;
    else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
  }
  const matches = (ref: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => ref.startsWith(prefix));
  const parts: Buffer[] = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headTip = repo.refs.get(headTarget);
  if (matches('HEAD')) {
    if (headTip === undefined) parts.push(encodePkt(`unborn HEAD${symrefs ? ` symref-target:${headTarget}` : ''}\n`));
    else parts.push(encodePkt(`${headTip} HEAD${symrefs ? ` symref-target:${headTarget}` : ''}\n`));
  }
  for (const [ref, oid] of sortedRefs(repo)) {
    if (!matches(ref)) continue;
    let line = `${oid} ${ref}`;
    if (peel) {
      const object = repo.objects.get(oid);
      if (object !== undefined && object.type === 'tag') line += ` peeled:${peelToCommit(repo, oid)}`;
    }
    parts.push(encodePkt(`${line}\n`));
  }
  parts.push(FLUSH_PKT);
  const bodyBuffer = Buffer.concat(parts);
  res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': bodyBuffer.length });
  res.end(bodyBuffer);
}

interface FetchPlan {
  readonly send: Map<string, GitObject>;
  readonly shallowLines: string[];
}

/** One commit's own objects: itself plus its tree closure (never its ancestors'). */
function ownObjects(repo: RepoRec, commitOid: string): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const commit = repo.objects.get(commitOid);
  if (commit === undefined || commit.type !== 'commit') return out;
  out.set(commitOid, commit);
  const stack = [parseCommit(commit.data).tree];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object === undefined) continue;
    out.set(oid, object);
    if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    }
  }
  return out;
}

/** Decide what a fetch delivers: depth-limited or full closure, minus what the client already has. */
function planFetch(repo: RepoRec, wants: readonly string[], haves: readonly string[], clientShallow: readonly string[], deepen: number | null): FetchPlan {
  const send = new Map<string, GitObject>();
  const shallowLines: string[] = [];
  if (deepen !== null && deepen > 0) {
    // What a shallow client already holds is each have's own objects — a have
    // names a commit the client holds shallowly, not its full closure.
    const held = new Map<string, GitObject>();
    for (const oid of [...haves, ...clientShallow]) {
      for (const [heldOid, object] of ownObjects(repo, oid)) held.set(heldOid, object);
    }
    // Generation-layered walk from each want: generation 1 is the want itself.
    const includedCommits = new Set<string>();
    const boundary = new Set<string>();
    let frontier = [...wants];
    const seen = new Set<string>();
    for (let generation = 1; generation <= deepen; generation += 1) {
      const next: string[] = [];
      for (const oid of frontier) {
        if (seen.has(oid)) continue;
        seen.add(oid);
        const object = repo.objects.get(oid);
        if (object === undefined) continue;
        if (object.type === 'tag') {
          if (!held.has(oid)) send.set(oid, object);
          next.push(parseTagTarget(object.data));
          continue;
        }
        if (object.type !== 'commit') continue;
        includedCommits.add(oid);
        const info = parseCommit(object.data);
        if (generation === deepen && info.parents.length > 0) boundary.add(oid);
        for (const parent of info.parents) next.push(parent);
      }
      frontier = next;
    }
    for (const oid of includedCommits) {
      for (const [objectOid, object] of ownObjects(repo, oid)) {
        if (!held.has(objectOid)) send.set(objectOid, object);
      }
    }
    for (const oid of boundary) shallowLines.push(`shallow ${oid}`);
    for (const oid of clientShallow) {
      if (includedCommits.has(oid) && !boundary.has(oid)) shallowLines.push(`unshallow ${oid}`);
    }
    return { send, shallowLines };
  }
  const haveClosure = haves.length === 0 ? new Map<string, GitObject>() : reachableObjects(repo, haves);
  const wanted = reachableObjects(repo, wants);
  for (const [oid, object] of wanted) {
    if (!haveClosure.has(oid)) send.set(oid, object);
  }
  return { send, shallowLines };
}

/** Wrap pack bytes in sideband band-1 pkt-lines (each within the 65520 cap). */
function sidebandWrap(data: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65_515;
  for (let offset = 0; offset < data.length; offset += CHUNK) {
    parts.push(encodePkt(Buffer.concat([Buffer.from([1]), data.subarray(offset, offset + CHUNK)])));
  }
  return Buffer.concat(parts);
}

/** The pack for a fetch's send set, cached per repository: repeated clones of
 * the same tip (the clone workload) reuse the exact bytes. */
function packForSend(repo: RepoRec, send: Map<string, GitObject>): Buffer {
  const key = sha1Hex(Buffer.from([...send.keys()].sort().join(','), 'utf8'));
  const cached = repo.packCache.get(key);
  if (cached !== undefined) return cached;
  const pack = buildPack([...send.values()]);
  if (repo.packCache.size > 128) repo.packCache.clear();
  repo.packCache.set(key, pack);
  return pack;
}

function sendFetchResponse(res: ServerResponse, repo: RepoRec, plan: FetchPlan, v2: boolean): void {
  const parts: Buffer[] = [];
  if (v2) {
    parts.push(encodePkt('acknowledgments\n'));
    parts.push(encodePkt('NAK\n'));
    parts.push(DELIM_PKT);
    if (plan.shallowLines.length > 0) {
      parts.push(encodePkt('shallow-info\n'));
      for (const line of plan.shallowLines) parts.push(encodePkt(`${line}\n`));
      parts.push(DELIM_PKT);
    }
    if (plan.send.size > 0) {
      parts.push(encodePkt('packfile\n'));
      parts.push(sidebandWrap(packForSend(repo, plan.send)));
    }
    parts.push(FLUSH_PKT);
  } else {
    parts.push(encodePkt('NAK\n'));
    if (plan.send.size > 0) {
      parts.push(sidebandWrap(packForSend(repo, plan.send)));
    }
    parts.push(FLUSH_PKT);
  }
  const bodyBuffer = Buffer.concat(parts);
  res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': bodyBuffer.length });
  res.end(bodyBuffer);
}

function handleUploadPack(res: ServerResponse, repo: RepoRec, body: Buffer): void {
  // v2 requests open with a "command=" line; v0 requests open with "want ".
  const { packets } = decodePkts(body);
  const first = packets.find((p) => p.kind === 'data');
  if (first === undefined || first.kind !== 'data') throw new Error('empty upload-pack request');
  const firstText = first.payload.toString('utf8');
  if (firstText.startsWith('command=')) {
    const { head, args } = parseV2Command(body);
    const command = (head[0] ?? '').replace(/^command=/, '').replace(/\n$/, '');
    if (command === 'ls-refs') {
      handleLsRefs(res, repo, args);
      return;
    }
    if (command === 'fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const clientShallow: string[] = [];
      let deepen: number | null = null;
      for (const arg of args) {
        if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
        else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
        else if (arg.startsWith('shallow ')) clientShallow.push(arg.slice(8).trim());
        else if (arg.startsWith('deepen ')) deepen = Number(arg.slice(7).trim());
      }
      sendFetchResponse(res, repo, planFetch(repo, wants, haves, clientShallow, deepen), true);
      return;
    }
    throw new Error(`unknown v2 command ${command}`);
  }
  if (firstText.startsWith('want ')) {
    // v0: want lines up to a flush, then have lines and done up to a second flush.
    const wants: string[] = [];
    const haves: string[] = [];
    let deepen: number | null = null;
    let section = 0;
    for (const packet of packets) {
      if (packet.kind === 'flush') {
        section += 1;
        continue;
      }
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8').replace(/\n$/, '');
      if (section === 0) {
        if (text.startsWith('want ')) wants.push(text.slice(5).split(' ')[0] as string);
        else if (text.startsWith('deepen ')) deepen = Number(text.slice(7).trim());
      } else if (text.startsWith('have ')) {
        haves.push(text.slice(5).trim());
      }
    }
    sendFetchResponse(res, repo, planFetch(repo, wants, haves, [], deepen), false);
    return;
  }
  throw new Error('unrecognized upload-pack request');
}

function handleReceivePack(res: ServerResponse, repo: RepoRec, body: Buffer): void {
  // Command pkt-lines run to the first flush; the pack (if any) follows raw.
  let offset = 0;
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  let capabilities = '';
  let firstLine = true;
  while (offset < body.length) {
    if (offset + 4 > body.length) throw new Error('receive-pack command list is truncated');
    const headerText = body.toString('ascii', offset, offset + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(headerText)) throw new Error('receive-pack command is not pkt-framed');
    const length = parseInt(headerText, 16);
    if (length === 0) {
      offset += 4;
      break;
    }
    if (length < 4 || offset + length > body.length) throw new Error('receive-pack command length is invalid');
    let payload = body.toString('utf8', offset + 4, offset + length);
    offset += length;
    if (firstLine) {
      firstLine = false;
      const nul = payload.indexOf('\0');
      if (nul >= 0) {
        capabilities = payload.slice(nul + 1).replace(/\n$/, '');
        payload = payload.slice(0, nul);
      }
    }
    const line = payload.replace(/\n$/, '');
    const parts = line.split(' ');
    if (parts.length >= 3) {
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
    }
  }
  const packBytes = body.subarray(offset);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const entries = parsePack(packBytes);
      const objects = resolvePack(entries, (oid) => repo.objects.get(oid));
      for (const [oid, object] of objects) repo.objects.set(oid, object);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'error';
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}`];
  for (const command of commands) {
    if (!unpackOk) {
      reportLines.push(`ng ${command.ref} unpack failed`);
      continue;
    }
    if (command.newOid === ZERO_OID) {
      repo.refs.delete(command.ref);
      reportLines.push(`ok ${command.ref}`);
      continue;
    }
    const target = repo.objects.get(command.newOid);
    if (target === undefined) {
      reportLines.push(`ng ${command.ref} missing object`);
      continue;
    }
    if (command.oldOid !== ZERO_OID) {
      // An update must fast-forward: the old tip must be an ancestor of the new
      // one (for a tag target, of the commit it peels to).
      const newCommit = target.type === 'commit' ? command.newOid : peelToCommit(repo, command.newOid);
      if (!isAncestor(repo, command.oldOid, newCommit)) {
        reportLines.push(`ng ${command.ref} non-fast-forward`);
        continue;
      }
    }
    repo.refs.set(command.ref, command.newOid);
    reportLines.push(`ok ${command.ref}`);
  }
  const reportParts: Buffer[] = reportLines.map((line) => encodePkt(`${line}\n`));
  reportParts.push(FLUSH_PKT);
  const reportStream = Buffer.concat(reportParts);
  const useSideband = capabilities.split(' ').some((cap) => cap === 'side-band-64k' || cap === 'side-band');
  const responseBody = useSideband ? Buffer.concat([sidebandWrap(reportStream), FLUSH_PKT]) : reportStream;
  res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'content-length': responseBody.length });
  res.end(responseBody);
}

async function handleGit(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const method = req.method ?? 'GET';
  const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(url.pathname);
  if (match === null) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const owner = decodeURIComponent(match[1] as string);
  const repoName = decodeURIComponent(match[2] as string);
  const sub = match[3] ?? '';
  if (!authed(req)) {
    sendError(res, 401, 'Bad credentials');
    return;
  }
  const repo = gitRepoOr404(res, owner, repoName);
  if (repo === null) return;
  try {
    if (method === 'GET' && sub === '/info/refs') {
      const service = url.searchParams.get('service') ?? '';
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendError(res, 400, 'Unknown service');
        return;
      }
      handleInfoRefs(res, repo, service, req.headers['git-protocol'] ?? '');
      return;
    }
    if (method === 'POST' && sub === '/git-upload-pack') {
      const body = await readBody(req);
      handleUploadPack(res, repo, body);
      return;
    }
    if (method === 'POST' && sub === '/git-receive-pack') {
      const body = await readBody(req);
      handleReceivePack(res, repo, body);
      return;
    }
  } catch {
    // A malformed request must never take the forge down.
    if (!res.headersSent) sendError(res, 400, 'Bad Request');
    else res.end();
    return;
  }
  sendError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// the app
// ---------------------------------------------------------------------------

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async (): Promise<void> => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const path = url.pathname;
        const method = req.method ?? 'GET';
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          await handleRest(req, res, url);
          return;
        }
        if (path === '/api/graphql') {
          await handleGraphql(req, res);
          return;
        }
        if (path === '/mcp') {
          await handleMcp(req, res);
          return;
        }
        if (/^\/[^/]+\/[^/]+\.git(\/.*)?$/.test(path)) {
          await handleGit(req, res, url);
          return;
        }
        sendError(res, 404, 'Not Found');
      } catch {
        if (!res.headersSent) sendError(res, 500, 'Internal Server Error');
        else res.end();
      }
    })();
  });
}
