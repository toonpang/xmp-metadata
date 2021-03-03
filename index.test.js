/**
 * https://www.npmjs.com/package/exiftool-vendored
 * Docs: https://photostructure.github.io/exiftool-vendored.js/modules.html
 *
 * Using exiftool-vendored, which is a nodejs wrapper around exiftool (https://exiftool.org)
 */

/**
 * This is where the exiftool config file (.ExifTool_config) should exists.
 * Without the config file, we cannot write custom xmp tags
 *
 * NOTE: This has to be before exiftool is initialized
 *
 * Another option is to move this env variable to package.json scripts
 */
process.env.EXIFTOOL_HOME = 'exiftoolHome/';

// =============================================================================
// Const
// =============================================================================
const crypto = require('crypto');
const fs = require('fs').promises;
const exiftool = require("exiftool-vendored").exiftool;
const uuid = require('uuid');

const { TextEncoder, TextDecoder } = require('util');
const { SigningAlgorithmSpec, KMS, KMSClient, SignCommand } = require("@aws-sdk/client-kms");
const KSM_KEY_ID = 'DUMMY';

const PROP1 = "Prop1";
const PROP2 = "Prop2";

const defaultAdditionalWriteArgs = ['-api', 'Compact=Shorthand'];

const removeFileAfterRunning = true;

// =============================================================================
// Functions
// =============================================================================
const removeOutputFiles = () => {
  let fs = require('fs')
  const path = './assets/'
  let regex = /.*OUT.*$/
  fs.readdirSync(path)
    .filter(f => regex.test(f))
    .map(f => fs.unlinkSync(path + f))
}

const stringToUint8Array = (input) => Buffer.of(input);
const uint8ArrayToHexString = (input) => Buffer.from(input).toString('hex');

const generateChecksum = (str) => {
  return crypto
    .createHash('sha512')
    .update(str, 'utf8')
    .digest('hex');
}

// =============================================================================
// Test
// =============================================================================

describe("XMP Metadata", () => {
  const kms = new KMS({
    region: 'ap-southeast-1',
    credentials: {
      accessKeyId: 'DUMMY',
      secretAccessKey: 'DUMMY/'
    }
  })

  beforeAll(async () => {
    const version = await exiftool.version();
    console.log(`We're running ExifTool v${version}`);
  })

  afterAll(async () => {
    await exiftool.end();

    if (removeFileAfterRunning) {
      removeOutputFiles();
    }

  })

  describe('For PDF', () => {
    it('Writing and reading tags', async () => {
      const path = "./assets/SAMPLE_PDF.pdf";
      const output = "./assets/SAMPLE_PDF_OUT.pdf";
      const expectedUuid = uuid.v4();
      const expectedSig = 'randomSig';

      await exiftool.write(path, {
        [PROP1]: expectedUuid,
        [PROP2]: expectedSig
      }, [...defaultAdditionalWriteArgs, "-o", output]);

      const tags = await exiftool.read(output);

      expect(tags[PROP1]).toEqual(expectedUuid);
      expect(tags[PROP2]).toEqual(expectedSig);
    });
  });

  describe('For JPEG', () => {
    it('Writing and reading tags', async () => {
      const path = "./assets/SAMPLE_JPEG.jpeg";
      const output = "./assets/SAMPLE_JPEG_OUT.jpeg";
      const expectedUuid = uuid.v4();
      const expectedSig = 'randomSig';

      await exiftool.write(path, {
        [PROP1]: expectedUuid,
        [PROP2]: expectedSig
      }, [...defaultAdditionalWriteArgs, "-o", output]);

      const tags = await exiftool.read(output);

      expect(tags[PROP1]).toEqual(expectedUuid);
      expect(tags[PROP2]).toEqual(expectedSig);
    });
  })

  describe('For PNG', () => {
    it('Writing and reading tags', async () => {
      const path = "./assets/SAMPLE_PNG.png";
      const output = "./assets/SAMPLE_PNG_OUT.png";
      const expectedUuid = uuid.v4();
      const expectedSig = 'randomSig';

      await exiftool.write(path, {
        [PROP1]: expectedUuid,
        [PROP2]: expectedSig
      }, [...defaultAdditionalWriteArgs, "-o", output]);

      const tags = await exiftool.read(output);

      expect(tags[PROP1]).toEqual(expectedUuid);
      expect(tags[PROP2]).toEqual(expectedSig);
    });
  })

  xdescribe('KMS', () => {
    it('Signing and verifying should not throw exception', async () => {
      const expectedUuid = uuid.v4();
      const { Signature } = await kms.sign({
        SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PSS_SHA_512,
        KeyId: KSM_KEY_ID,
        Message: stringToUint8Array(expectedUuid),
      });

      const verifyRes = await kms.verify({
        SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PSS_SHA_512,
        KeyId: KSM_KEY_ID,
        Message: stringToUint8Array(expectedUuid),
        Signature,
      });

      expect(verifyRes.SignatureValid).toEqual(true);
    });
  })

  describe('Hashing', () => {

    it('Hash should be same for the same document', async () => {
      const input = './assets/SAMPLE_PNG.png';

      expect(generateChecksum(await fs.readFile(input))).toEqual(generateChecksum(await fs.readFile(input)));
    })

    it('The hash before and after xmp tagging is should be different', async () => {
      const input = './assets/SAMPLE_PNG.png';
      const output = './assets/SAMPLE_PNG_HASHING_BEFORE_AFTER_OUT.png';

      const expectedUuid = uuid.v4();
      const expectedSig = 'dummySig';

      await exiftool.write(input, {
        [PROP1]: expectedUuid,
        [PROP2]: expectedSig,
      }, [...defaultAdditionalWriteArgs, "-o", output]);

      const checksumOriginal = generateChecksum(await fs.readFile(input));
      const checksumNew = generateChecksum(await fs.readFile(output));
      expect(checksumNew).not.toEqual(checksumOriginal);

      const tags = await exiftool.read(output);
      expect(tags[PROP1]).toEqual(expectedUuid);
      expect(tags[PROP2]).toEqual(expectedSig);
    })

    it('Hash should be same for tagged documents with same Prop1 and Prop2', async () => {
      const input = './assets/SAMPLE_PNG.png';
      const output1 = './assets/SAMPLE_PNG_HASHING_AFTER_OUT_1.png';
      const output2 = './assets/SAMPLE_PNG_HASHING_AFTER_OUT_2.png';

      const expectedUuid = uuid.v4();
      const expectedSig = 'dummySig';

      await exiftool.write(input, {
        [PROP1]: expectedUuid,
        [PROP2]: expectedSig,
      }, [...defaultAdditionalWriteArgs, "-o", output1]);

      await exiftool.write(input, {
        [PROP1]: expectedUuid,
        [PROP2]: expectedSig,
      }, [...defaultAdditionalWriteArgs, "-o", output2]);

      expect(generateChecksum(await fs.readFile(output1))).toEqual(generateChecksum(await fs.readFile(output2)));
    })
  });
})
