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
jest.setTimeout(30000);
// =============================================================================
// Const
// =============================================================================
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const crypto = require('crypto');
const fs = require('fs').promises;
const exiftool = require("exiftool-vendored").exiftool;
const uuid = require('uuid');

const { SigningAlgorithmSpec, KMS, KMSClient, SignCommand } = require("@aws-sdk/client-kms");
const KSM_KEY_ID = 'DUMMY';

const PROP1 = "Prop1";
const PROP2 = "Prop2";

const defaultAdditionalWriteArgs = ['-api', 'Compact=Shorthand'];

const removeFileAfterRunning = true;

// =============================================================================
// Functions
// =============================================================================
const removeOutputFiles = async (path) => {
  let regex = /.*OUT.*$/

  const filePaths = await fs.readdir(path);
  await Promise.all(filePaths.filter(f => regex.test(f)).map(async (f) => await fs.unlink(path + f)));
}

const deleteFile = async (path) => {
  await fs.unlink(path);
}

const renameFile = async (src, dest) => {
  await fs.rename(src, dest);
}

const stringToUint8Array = (input) => Buffer.of(input);
const uint8ArrayToHexString = (input) => Buffer.from(input).toString('hex');

const generateChecksum = (str) => {
  return crypto
    .createHash('sha512')
    .update(str, 'utf8')
    .digest('hex');
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

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
      await removeOutputFiles('./assets/');
      await removeOutputFiles('./assets2/')
    }
  })

  xdescribe('Signing', () => {
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
  });

  describe('Tagging', () => {
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
  });

  describe('Hashing', () => {

    describe('For PNG', () => {
      it('Hash should be same for the same document', async () => {
        const input = './assets/SAMPLE_PNG.png';

        expect(generateChecksum(await fs.readFile(input))).toEqual(generateChecksum(await fs.readFile(input)));
      })

      it('The hash before and after xmp tagging should be different', async () => {
        const input = './assets/SAMPLE_PNG.png';
        const output = './assets/SAMPLE_PNG_HASHING_BEFORE_AFTER_OUT.png';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output]);

        // ensure the tags are written
        const tags = await exiftool.read(output);
        expect(tags[PROP1]).toEqual(expectedUuid);
        expect(tags[PROP2]).toEqual(expectedSig);

        const checksumOriginal = generateChecksum(await fs.readFile(input));
        const checksumNew = generateChecksum(await fs.readFile(output));
        expect(checksumNew).not.toEqual(checksumOriginal);
      })

      it('The hash should be different if tagged with different uuid', async () => {
        const input = './assets/SAMPLE_PNG.png';
        const output1 = './assets/SAMPLE_PNG_DIFFERENT_UUID_OUT_1.png'
        const output2 = './assets/SAMPLE_PNG_DIFFERENT_UUID_OUT_2.png'

        const expectedUuid1 = uuid.v4();
        const expectedUuid2 = uuid.v4();

        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid1,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        await exiftool.write(input, {
          [PROP1]: expectedUuid2,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output2]);

        // ensure the tags are written
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid1);
        expect(tags1[PROP2]).toEqual(expectedSig);

        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid2);
        expect(tags2[PROP2]).toEqual(expectedSig);

        // ensure the checksum are diff
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        expect(checksum1).not.toEqual(checksum2);
      })

      it('The hash should be different if tagged with different sig', async () => {
        const input = './assets/SAMPLE_PNG.png';
        const output1 = './assets/SAMPLE_PNG_DIFFERENT_SIG_OUT_1.png'
        const output2 = './assets/SAMPLE_PNG_DIFFERENT_SIG_OUT_2.png'

        const expectedUuid = uuid.v4();

        const expectedSig1 = 'dummySig-1';
        const expectedSig2 = 'dummySig-2';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig1,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig2,
        }, [...defaultAdditionalWriteArgs, "-o", output2]);

        // ensure the tags are written
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid);
        expect(tags1[PROP2]).toEqual(expectedSig1);

        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid);
        expect(tags2[PROP2]).toEqual(expectedSig2);

        // ensure the checksum are diff
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        expect(checksum1).not.toEqual(checksum2);
      })

      it('The hash should be the same if the same file is tagged with same uuid and sig and output twice', async () => {
        const input = './assets/SAMPLE_PNG.png';
        const output1 = './assets/SAMPLE_PNG_TAGGED_TWICE_OUT_1.png'
        const output2 = './assets/SAMPLE_PNG_TAGGED_TWICE_OUT_2.png'

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

        // ensure the tags are written
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid);
        expect(tags1[PROP2]).toEqual(expectedSig);

        // ensure the tags are written
        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid);
        expect(tags2[PROP2]).toEqual(expectedSig);

        // ensure the checksum are the same
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        expect(checksum1).toEqual(checksum2);
      })

      it('The hash for output1 and output3 should be the same if they have same uuid and sig (input -> output1 -> output2 (diff uuid / sig) -> output3)', async () => {
        const input = './assets/SAMPLE_PNG.png';
        const output1 = './assets/SAMPLE_PNG_RETAGGED_OUT_1.png';
        const output2 = './assets/SAMPLE_PNG_RETAGGED_OUT_2.png';
        const output3 = './assets/SAMPLE_PNG_RETAGGED_OUT_3.png';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        const expectedUuid2 = uuid.v4();
        const expectedSig2 = 'ANOTHER_SIG';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        await exiftool.write(output1, {
          [PROP1]: expectedUuid2,
          [PROP2]: expectedSig2,
        }, [...defaultAdditionalWriteArgs, "-o", output2]);

        await exiftool.write(output2, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output3]);

        // ---------------------------------------------------------------------
        // ensure the tags are written
        // ---------------------------------------------------------------------
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid);
        expect(tags1[PROP2]).toEqual(expectedSig);

        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid2);
        expect(tags2[PROP2]).toEqual(expectedSig2);


        const tags3 = await exiftool.read(output3);
        expect(tags3[PROP1]).toEqual(expectedUuid);
        expect(tags3[PROP2]).toEqual(expectedSig);

        // ---------------------------------------------------------------------
        // Ensure checksum
        // ---------------------------------------------------------------------
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        const checksum3 = generateChecksum(await fs.readFile(output3));
        expect(checksum1).not.toEqual(checksum2);
        expect(checksum2).not.toEqual(checksum3);
        expect(checksum1).toEqual(checksum3);
      })

      it('The hash after deleting all tags should be the same', async () => {
        const input = './assets/SAMPLE_PNG_DELETE_TAGS.png';
        const output = './assets/SAMPLE_PNG_DELETE_TAGS_OUT.png';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output]);

        // ensure the tags are written
        const tags = await exiftool.read(output);
        expect(tags[PROP1]).toEqual(expectedUuid);
        expect(tags[PROP2]).toEqual(expectedSig);

        await exiftool.deleteAllTags(input);
        await exiftool.deleteAllTags(output);

        // ensure the written tags are removed
        const tagsAfterDelete = await exiftool.read(output);
        expect(tagsAfterDelete[PROP1]).toEqual(undefined);
        expect(tagsAfterDelete[PROP2]).toEqual(undefined);

        // ensure the checksum are the same
        const checksumOriginal = generateChecksum(await fs.readFile(input));
        const checksumNew = generateChecksum(await fs.readFile(output));
        expect(checksumNew).toEqual(checksumOriginal);

        // Clean up
        await deleteFile(input);
        await renameFile(`${input}_original`, input);
      })

      it('The hash after moving and renaming should be the same', async () => {
        const input = './assets/SAMPLE_PNG_DELETE_TAGS.png';
        const output1 = './assets/SAMPLE_PNG_RENAMED_OUT_1.png';
        const output2 = './assets2/SAMPLE_PNG_RENAMED_OUT_2.png';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        const checksum1 = generateChecksum(await fs.readFile(output1));

        await renameFile(output1, output2);
        const checksum2 = generateChecksum(await fs.readFile(output2));

        expect(checksum1).toEqual(checksum2);
      })

      it('The hash after opening the file should be the same', async () => {
        const input = './assets/SAMPLE_PNG.png';
        const output = './assets/SAMPLE_PNG_OPENED_OUT_1.png';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output]);

        const accessDateSecondBefore = (await exiftool.read(output)).FileAccessDate.second;
        const checksumBefore = generateChecksum(await fs.readFile(output));

        // Wait for 3 seconds before opening
        await sleep(3000);
        const { stdout, stderr } = await exec(`open ${output}`);
        await sleep(3000);

        const accessDateSecondAfter = (await exiftool.read(output)).FileAccessDate.second;
        const checksumAfter = generateChecksum(await fs.readFile(output));

        expect(accessDateSecondBefore).not.toEqual(accessDateSecondAfter);
        expect(checksumBefore).toEqual(checksumAfter);
      })
    })

    describe('For JPEG', () => {
      it('Hash should be same for the same document', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';

        expect(generateChecksum(await fs.readFile(input))).toEqual(generateChecksum(await fs.readFile(input)));
      })

      it('The hash before and after xmp tagging should be different', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';
        const output = './assets/SAMPLE_JPEG_HASHING_BEFORE_AFTER_OUT.jpeg';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output]);

        // ensure the tags are written
        const tags = await exiftool.read(output);
        expect(tags[PROP1]).toEqual(expectedUuid);
        expect(tags[PROP2]).toEqual(expectedSig);

        const checksumOriginal = generateChecksum(await fs.readFile(input));
        const checksumNew = generateChecksum(await fs.readFile(output));
        expect(checksumNew).not.toEqual(checksumOriginal);
      })

      it('The hash should be different if tagged with different uuid', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';
        const output1 = './assets/SAMPLE_JPEG_DIFFERENT_UUID_OUT_1.jpeg'
        const output2 = './assets/SAMPLE_JPEG_DIFFERENT_UUID_OUT_2.jpeg'

        const expectedUuid1 = uuid.v4();
        const expectedUuid2 = uuid.v4();

        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid1,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        await exiftool.write(input, {
          [PROP1]: expectedUuid2,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output2]);

        // ensure the tags are written
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid1);
        expect(tags1[PROP2]).toEqual(expectedSig);

        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid2);
        expect(tags2[PROP2]).toEqual(expectedSig);

        // ensure the checksum are diff
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        expect(checksum1).not.toEqual(checksum2);
      })

      it('The hash should be different if tagged with different sig', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';
        const output1 = './assets/SAMPLE_JPEG_DIFFERENT_SIG_OUT_1.jpeg'
        const output2 = './assets/SAMPLE_JPEG_DIFFERENT_SIG_OUT_2.jpeg'

        const expectedUuid = uuid.v4();

        const expectedSig1 = 'dummySig-1';
        const expectedSig2 = 'dummySig-2';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig1,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig2,
        }, [...defaultAdditionalWriteArgs, "-o", output2]);

        // ensure the tags are written
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid);
        expect(tags1[PROP2]).toEqual(expectedSig1);

        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid);
        expect(tags2[PROP2]).toEqual(expectedSig2);

        // ensure the checksum are diff
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        expect(checksum1).not.toEqual(checksum2);
      })

      it('The hash should be the same if the same file is tagged with same uuid and sig and output twice', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';
        const output1 = './assets/SAMPLE_JPEG_TAGGED_TWICE_OUT_1.jpeg'
        const output2 = './assets/SAMPLE_JPEG_TAGGED_TWICE_OUT_2.jpeg'

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

        // ensure the tags are written
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid);
        expect(tags1[PROP2]).toEqual(expectedSig);

        // ensure the tags are written
        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid);
        expect(tags2[PROP2]).toEqual(expectedSig);

        // ensure the checksum are the same
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        expect(checksum1).toEqual(checksum2);
      })

      it('The hash for output1 and output3 should be the same if they have same uuid and sig (input -> output1 -> output2 (diff uuid / sig) -> output3)', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';
        const output1 = './assets/SAMPLE_JPEG_RETAGGED_OUT_1.jpeg';
        const output2 = './assets/SAMPLE_JPEG_RETAGGED_OUT_2.jpeg';
        const output3 = './assets/SAMPLE_JPEG_RETAGGED_OUT_3.jpeg';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        const expectedUuid2 = uuid.v4();
        const expectedSig2 = 'ANOTHER_SIG';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        await exiftool.write(output1, {
          [PROP1]: expectedUuid2,
          [PROP2]: expectedSig2,
        }, [...defaultAdditionalWriteArgs, "-o", output2]);

        await exiftool.write(output2, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output3]);

        // ---------------------------------------------------------------------
        // ensure the tags are written
        // ---------------------------------------------------------------------
        const tags1 = await exiftool.read(output1);
        expect(tags1[PROP1]).toEqual(expectedUuid);
        expect(tags1[PROP2]).toEqual(expectedSig);

        const tags2 = await exiftool.read(output2);
        expect(tags2[PROP1]).toEqual(expectedUuid2);
        expect(tags2[PROP2]).toEqual(expectedSig2);


        const tags3 = await exiftool.read(output3);
        expect(tags3[PROP1]).toEqual(expectedUuid);
        expect(tags3[PROP2]).toEqual(expectedSig);

        // ---------------------------------------------------------------------
        // Ensure checksum
        // ---------------------------------------------------------------------
        const checksum1 = generateChecksum(await fs.readFile(output1));
        const checksum2 = generateChecksum(await fs.readFile(output2));
        const checksum3 = generateChecksum(await fs.readFile(output3));
        expect(checksum1).not.toEqual(checksum2);
        expect(checksum2).not.toEqual(checksum3);
        expect(checksum1).toEqual(checksum3);
      })

      it('The hash after deleting all tags should be the same', async () => {
        const input = './assets/SAMPLE_JPEG_DELETE_TAGS.jpeg';
        const output = './assets/SAMPLE_JPEG_DELETE_TAGS_OUT.jpeg';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output]);

        // ensure the tags are written
        const tags = await exiftool.read(output);
        expect(tags[PROP1]).toEqual(expectedUuid);
        expect(tags[PROP2]).toEqual(expectedSig);

        await exiftool.deleteAllTags(input);
        await exiftool.deleteAllTags(output);

        // ensure the written tags are removed
        const tagsAfterDelete = await exiftool.read(output);
        expect(tagsAfterDelete[PROP1]).toEqual(undefined);
        expect(tagsAfterDelete[PROP2]).toEqual(undefined);

        // ensure the checksum are the same
        const checksumOriginal = generateChecksum(await fs.readFile(input));
        const checksumNew = generateChecksum(await fs.readFile(output));
        expect(checksumNew).toEqual(checksumOriginal);

        // Clean up
        await deleteFile(input);
        await renameFile(`${input}_original`, input);
      })

      it('The hash after moving and renaming should be the same', async () => {
        const input = './assets/SAMPLE_JPEG_DELETE_TAGS.jpeg';
        const output1 = './assets/SAMPLE_JPEG_RENAMED_OUT_1.jpeg';
        const output2 = './assets2/SAMPLE_JPEG_RENAMED_OUT_2.jpeg';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output1]);

        const checksum1 = generateChecksum(await fs.readFile(output1));

        await renameFile(output1, output2);
        const checksum2 = generateChecksum(await fs.readFile(output2));

        expect(checksum1).toEqual(checksum2);
      })

      it('The hash after opening the file should be the same', async () => {
        const input = './assets/SAMPLE_JPEG.jpeg';
        const output = './assets/SAMPLE_JPEG_OPENED_OUT_1.jpeg';

        const expectedUuid = uuid.v4();
        const expectedSig = 'dummySig';

        await exiftool.write(input, {
          [PROP1]: expectedUuid,
          [PROP2]: expectedSig,
        }, [...defaultAdditionalWriteArgs, "-o", output]);

        const accessDateSecondBefore = (await exiftool.read(output)).FileAccessDate.second;
        const checksumBefore = generateChecksum(await fs.readFile(output));

        // Wait for 3 seconds before opening
        await sleep(3000);
        const { stdout, stderr } = await exec(`open ${output}`);
        await sleep(3000);

        const accessDateSecondAfter = (await exiftool.read(output)).FileAccessDate.second;
        const checksumAfter = generateChecksum(await fs.readFile(output));

        expect(accessDateSecondBefore).not.toEqual(accessDateSecondAfter);
        expect(checksumBefore).toEqual(checksumAfter);
      })
    })

    describe('For PDF', () => {
      it('Hash should be same for the same document', async () => {
        const input = './assets/SAMPLE_PDF.pdf';

        expect(generateChecksum(await fs.readFile(input))).toEqual(generateChecksum(await fs.readFile(input)));
      })
    })

    /**
     *   The checksum will be the same after exiftool.deleteAllTags for PNG and JPEG.
     *   It will not be the same for pdf
     */
    // it('The hash before and after xmp tagging is should be different', async () => {
    //   const input = './assets/SAMPLE_PNG.jpeg';
    //   const output = './assets/SAMPLE_PNG_HASHING_BEFORE_AFTER_OUT.jpeg';

    //   const expectedUuid = uuid.v4();
    //   const expectedSig = 'dummySig';

    //   await exiftool.write(input, {
    //     [PROP1]: expectedUuid,
    //     [PROP2]: expectedSig,
    //   }, [...defaultAdditionalWriteArgs, "-o", output]);

    //   const checksumOriginal = generateChecksum(await fs.readFile(input));
    //   const checksumNew = generateChecksum(await fs.readFile(output));
    //   expect(checksumNew).not.toEqual(checksumOriginal);

    //   const tags = await exiftool.read(output);
    //   expect(tags[PROP1]).toEqual(expectedUuid);
    //   expect(tags[PROP2]).toEqual(expectedSig);
    // })

    // it('Hash should be same for tagged documents with same Prop1 and Prop2', async () => {
    //   const input = './assets/SAMPLE_PNG.png';
    //   const output1 = './assets/SAMPLE_PNG_HASHING_AFTER_OUT_1.png';
    //   const output2 = './assets/SAMPLE_PNG_HASHING_AFTER_OUT_2.png';

    //   const expectedUuid = uuid.v4();
    //   const expectedSig = 'dummySig';

    //   await exiftool.write(input, {
    //     [PROP1]: expectedUuid,
    //     [PROP2]: expectedSig,
    //   }, [...defaultAdditionalWriteArgs, "-o", output1]);

    //   await exiftool.write(input, {
    //     [PROP1]: expectedUuid,
    //     [PROP2]: expectedSig,
    //   }, [...defaultAdditionalWriteArgs, "-o", output2]);

    //   expect(generateChecksum(await fs.readFile(output1))).toEqual(generateChecksum(await fs.readFile(output2)));
    // })
  });
})
