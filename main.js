/*
* Copyright ©2020 handshake.moe
* All rights reserved
*/

const boxen = require('boxen');
const chalk = require('chalk');
const clear = require('clear');
const assert = require('bsert');
const inquirer = require('listr-inquirer');
const Listr = require('listr');
const os = require('os');
const fs = require('bfile');
const request = require('brq');
const Path = require('path');
const bio = require('bufio');
const pgp = require('bcrypto/lib/pgp');
const ssh = require('bcrypto/lib/ssh');
const bech32 = require('bcrypto/lib/encoding/bech32');
const blake2b = require('bcrypto/lib/blake2b');
const sha256 = require('bcrypto/lib/sha256');
const merkle = require('bcrypto/lib/mrkl');
const HKDF = require('bcrypto/lib/hkdf');
const fixed = require('./lib/fixed');
const AirdropKey = require('./lib/key');
const AirdropProof = require('./lib/proof');
const readline = require('./lib/readline');
const pkg = require('./package.json');
const tree = require('./etc/tree.json');
const faucet = require('./etc/faucet.json');
const {PGPMessage, SecretKey} = pgp;
const {SSHPrivateKey} = ssh;
const {readLine, readPassphrase} = readline;

let BUILD_DIR = Path.resolve(os.homedir(), '.hs-tree-data');
const NONCE_DIR = Path.resolve(BUILD_DIR, 'nonces');
const GITHUB_URL = 'https://github.com/handshake-org/hs-tree-data/raw/master';
const PROOF_SUBMIT_URL = 'https://us-central1-handshake-a6cef.cloudfunctions.net/ingestProof';

const {
  PUBLIC_KEY,
  PRIVATE_KEY
} = pgp.packetTypes;

const {
  checksum: TREE_CHECKSUM,
  leaves: TREE_LEAVES,
  subleaves: SUBTREE_LEAVES,
  checksums: TREE_CHECKSUMS
} = tree;

const DEFAULT_KEY_PATH = Path.join(os.homedir(), '.ssh', 'id_rsa')
const ADDRESS = 'hs1qcrgzrmfzy3uj338vkcmvr94flnanv33ean7ch7';

const header = `
██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗██████╗ 
██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔══██╗
███████║███████║██╔██╗ ██║██║  ██║███████╗███████║███████║█████╔╝ ██████╔╝
██╔══██║██╔══██║██║╚██╗██║██║  ██║╚════██║██╔══██║██╔══██║██╔═██╗ ██╔══██╗
██║  ██║██║  ██║██║ ╚████║██████╔╝███████║██║  ██║██║  ██║██║  ██╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
                                                      
easy HNS airdrop claimer
v0.0.2
source: https://github.com/handshakemoe/handshakr/blob/master/main.js`

async function createKeyProofs(options) {
  assert(options != null && options.key != null);
  assert(options.key.pub instanceof AirdropKey);

  const {pub, priv} = options.key;

  console.log('Decrypting nonce...');

  const items = await findNonces(pub, priv);

  console.log('Found nonce!');
  console.log('Rebuilding tree...');

  const leaves = await readLeaves();
  const tree = flattenLeaves(leaves);
  const proofs = [];

  for (const [i, [nonce, seed]] of items.entries()) {
    const key = pub.clone();

    if (options.bare)
      key.applyNonce(nonce);
    else
      key.applyTweak(nonce);

    console.log('Finding merkle leaf for reward %d...', i);

    const [index, subindex] = findLeaf(leaves, key.hash());

    if (index === -1)
      throw new Error('Could not find leaf.');

    const subtree = leaves[index];

    diffSubtree(key, nonce, seed, subtree);

    console.log('Creating proof from leaf %d:%d...', index, subindex);

    const subproof = merkle.createBranch(blake2b, subindex, subtree);
    const proof = merkle.createBranch(blake2b, index, tree);
    const p = new AirdropProof();

    p.index = index;
    p.proof = proof;
    p.subindex = subindex;
    p.subproof = subproof;
    p.key = key.encode();
    p.version = options.version;
    p.address = options.hash;
    p.fee = options.fee;

    if (p.fee > p.getValue())
      throw new Error('Fee exceeds value!');

    console.log('Signing proof %d:%d...', index, subindex);

    p.sign(key, priv);

    if (!p.verify())
      throw new Error('Proof failed verification.');

    proofs.push(p);
  }

  return proofs;
}

async function readFile(...path) {
  if (!await fs.exists(BUILD_DIR))
    await fs.mkdir(BUILD_DIR, 0o755);

  if (!await fs.exists(NONCE_DIR))
    await fs.mkdir(NONCE_DIR, 0o755);

  const checksum = Buffer.from(path.pop(), 'hex');
  const file = Path.resolve(BUILD_DIR, ...path);
  const base = Path.basename(file);

  if (!await fs.exists(file)) {
    const url = `${GITHUB_URL}/${path.join('/')}`;

    console.log('Downloading: %s...', url);

    const req = await request({
      url,
      limit: 100 << 20,
      timeout: 10 * 60 * 1000
    });

    const raw = req.buffer();

    if (!sha256.digest(raw).equals(checksum))
      throw new Error(`Invalid checksum: ${base}`);

    await fs.writeFile(file, raw);

    return raw;
  }

  const raw = await fs.readFile(file);

  if (!sha256.digest(raw).equals(checksum))
    throw new Error(`Invalid checksum: ${base}`);

  return raw;
}

async function readTreeFile() {
  return readFile('tree.bin', TREE_CHECKSUM);
}

async function readFaucetFile() {
  return readFile('faucet.bin', FAUCET_CHECKSUM);
}

async function readNonceFile(index) {
  assert((index & 0xff) === index);
  return readFile('nonces', `${pad(index)}.bin`, TREE_CHECKSUMS[index]);
}

async function readProofFile() {
  const raw = await readFile('proof.json', PROOF_CHECKSUM);
  return JSON.parse(raw.toString('utf8'));
}

async function readLeaves() {
  const data = await readTreeFile();
  const br = bio.read(data);
  const totalLeaves = br.readU32();
  const leaves = [];

  for (let i = 0; i < totalLeaves; i++) {
    const hashes = [];

    for (let j = 0; j < SUBTREE_LEAVES; j++) {
      const hash = br.readBytes(32, true);
      hashes.push(hash);
    }

    leaves.push(hashes);
  }

  assert.strictEqual(br.left(), 0);
  assert.strictEqual(totalLeaves, TREE_LEAVES);

  return leaves;
}

function flattenLeaves(leaves) {
  assert(Array.isArray(leaves));

  const out = [];

  for (const hashes of leaves) {
    const root = merkle.createRoot(blake2b, hashes);
    out.push(root);
  }

  return out;
}

function findLeaf(leaves, target) {
  assert(Array.isArray(leaves));
  assert(Buffer.isBuffer(target));

  for (let i = 0; i < leaves.length; i++) {
    const hashes = leaves[i];

    // Could do a binary search here.
    for (let j = 0; j < hashes.length; j++) {
      const hash = hashes[j];

      if (hash.equals(target))
        return [i, j];
    }
  }

  return [-1, -1];
}

async function readFaucetLeaves() {
  const data = await readFaucetFile();
  const br = bio.read(data);
  const totalLeaves = br.readU32();
  const leaves = [];

  for (let i = 0; i < totalLeaves; i++) {
    const hash = br.readBytes(32);
    leaves.push(hash);
  }

  assert.strictEqual(br.left(), 0);
  assert.strictEqual(totalLeaves, FAUCET_LEAVES);

  return leaves;
}

function findFaucetLeaf(leaves, target) {
  assert(Array.isArray(leaves));
  assert(Buffer.isBuffer(target));

  // Could do a binary search here.
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i];

    if (leaf.equals(target))
      return i;
  }

  return -1;
}

async function findNonces(key, priv) {
  assert(key instanceof AirdropKey);
  assert((priv instanceof SecretKey)
      || (priv instanceof SSHPrivateKey));

  const bucket = key.bucket();
  const data = await readNonceFile(bucket);
  const br = bio.read(data);
  const out = [];

  while (br.left()) {
    const ct = br.readBytes(br.readU16(), true);

    try {
      out.push(key.decrypt(ct, priv));
    } catch (e) {
      continue;
    }
  }

  if (out.length === 0) {
    const err = new Error();
    err.name = 'NonceError';
    err.message = `Could not find nonce in bucket ${bucket}.`;
    throw err;
  }

  return out;
}

function diffSubtree(key, nonce, seed, subtree) {
  assert(key instanceof AirdropKey);
  assert(Buffer.isBuffer(seed));
  assert(Array.isArray(subtree));

  const hkdf = new HKDF(sha256, seed);
  const hashes = [];

  while (hashes.length < SUBTREE_LEAVES)
    hashes.push(hkdf.generate(32));

  // Filter out synthetic hashes.
  // This basically proves that the generation
  // script did not do anything malicious. It
  // also informs the user that other keys are
  // available to use.
  const keyHashes = [];

  for (const hash of subtree) {
    let synthetic = false;

    for (const h of hashes) {
      if (h.equals(hash)) {
        synthetic = true;
        break;
      }
    }

    if (!synthetic)
      keyHashes.push(hash);
  }

  console.log('');
  console.log('%d keys found in your subtree:', keyHashes.length);

  const keyHash = key.hash();

  for (const hash of keyHashes) {
    if (keyHash.equals(hash))
      console.log('  %s (current)', hash.toString('hex'));
    else
      console.log('  %s', hash.toString('hex'));
  }

  console.log('');
}
/*
 * CLI
 */

async function parsePGP(msg, keyID) {
  assert(msg instanceof PGPMessage);
  assert(Buffer.isBuffer(keyID));

  let priv = null;
  let pub = null;

  for (const pkt of msg.packets) {
    if (pkt.type === PRIVATE_KEY) {
      const key = pkt.body;

      if (key.key.matches(keyID)) {
        priv = key;
        pub = key.key;
        continue;
      }

      continue;
    }

    if (pkt.type === PUBLIC_KEY) {
      const key = pkt.body;

      if (key.matches(keyID)) {
        pub = key;
        continue;
      }

      continue;
    }
  }

  if (!priv && !pub)
    throw new Error(`Could not find key for ID: ${keyID}.`);

  if (!priv) {
    return {
      type: 'pgp',
      pub: AirdropKey.fromPGP(pub),
      priv: null
    };
  }

  let passphrase = null;

  if (priv.params.encrypted) {
    console.log(`I found key ${pgp.encodeID(keyID)}, but it's encrypted.`);

    passphrase = await readPassphrase();
  }

  return {
    type: 'pgp',
    pub: AirdropKey.fromPGP(priv.key),
    priv: priv.secret(passphrase)
  };
}

function getType(arg) {
  assert(typeof arg === 'string');

  const ext = Path.extname(arg);

  switch (ext) {
    case '.asc':
    case '.pgp':
    case '.gpg':
      return 'pgp';
    default:
      return bech32.test(arg) ? 'addr' : 'ssh';
  }
}

async function readKey(file, keyID, passphrase) {
  assert(typeof file === 'string');
  assert(keyID == null || Buffer.isBuffer(keyID));

  const data = await fs.readFile(file);
  const ext = Path.extname(file);

  switch (ext) {
    case '.asc': {
      assert(keyID);
      const str = data.toString('utf8');
      const msg = PGPMessage.fromString(str);
      return parsePGP(msg, keyID);
    }

    case '.pgp':
    case '.gpg': {
      assert(keyID);
      const msg = PGPMessage.decode(data);
      return parsePGP(msg, keyID);
    }

    default: {
      const str = data.toString('utf8');
      const key = SSHPrivateKey.fromString(str, passphrase);
      return {
        type: 'ssh',
        pub: AirdropKey.fromSSH(key),
        priv: key
      };
    }
  }
}

async function readEntries(addr) {
  const [, target] = parseAddress(addr);
  const items = await readProofFile();
  const out = [];

  for (const [address, value, sponsor] of items) {
    const [, hash] = parseAddress(address);

    if (!hash.equals(target))
      continue;

    out.push({
      type: 'addr',
      pub: AirdropKey.fromAddress(addr, value, sponsor),
      priv: null
    });
  }

  if (out.length === 0)
    throw new Error('Address is not a faucet or sponsor address.');

  return out;
}

function pad(index) {
  assert((index & 0xff) === index);

  let str = index.toString(10);

  while (str.length < 3)
    str = '0' + str;

  return str;
}

function parseAddress(addr) {
  const [hrp, version, hash] = bech32.decode(addr);

  if (hrp !== 'hs' && hrp !== 'ts' && hrp !== 'rs')
    throw new Error('Invalid address HRP.');

  if (version !== 0)
    throw new Error('Invalid address version.');

  if (hash.length !== 20 && hash.length !== 32)
    throw new Error('Invalid address.');

  return [version, hash];
}

const tasks = new Listr([
  {
    title: 'Searching for key...',
    task: () => {
      return fs.existsSync(DEFAULT_KEY_PATH);
    },
  },
  {
    title: `Key found at ${DEFAULT_KEY_PATH}!`,
    task: (ctx, task) => inquirer([
			{
                type: 'password',
                name: 'sshPassphrase',
                message: 'Please enter your SSH key passphrase.'
            }
		], function (answers) {
      ctx.sshPassphrase = answers.sshPassphrase;
		})
  },
  {
    title: 'Reading key...',
    task: async (ctx) => ctx.key = await readKey(DEFAULT_KEY_PATH, null, ctx.sshPassphrase),
  },
  {
    title: 'Creating proof... (This may take 5-10 minutes. Please do not close this window)',
    task: async (ctx) => {
      const options = {
        addr: ADDRESS,
        bare: false,
        entries: [],
        key: ctx.key,
        fee: fixed.decode('0.5', 6),
        type: 'ssh',
        version: 0,
      };
      [options.version, options.hash] = parseAddress(options.addr);
      ctx.proofs = await createKeyProofs(options);
    }
  },
  {
    title: 'Proof created! Sending proof...',
    task: async (ctx) => {
      const proof = ctx.proofs[0];
      const res = await request({
        url: PROOF_SUBMIT_URL,
        method: 'POST',
        json: {
          base64: proof.toBase64(),
          proof,
        }
      });
      const json = await res.json();
      ctx.proofId = json.proofId;
    }
  }
], {
});

const main = async () => {
  clear();
  console.log(chalk.magentaBright(boxen(header, {padding: 1, margin: {bottom: 1}, align: 'center'})));
  
  const ctx = await tasks.run();

  console.log(chalk.magentaBright(boxen(
    chalk.bold('🎉 All done! 🎉') + '\n' +
    'Click your personal proof link below to continue claiming your tokens: ' + '\n' +
    chalk.bold(`https://handshake.moe/claim/${ctx.proofId}`)
    , {padding: 1, margin: {top: 1, bottom: 1}, align: 'center'})));
};

main();
