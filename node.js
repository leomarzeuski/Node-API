const express = require('express');
const axios = require('axios');
const fs = require('fs');
const AWS = require('aws-sdk');
const pem = require('pem');
const signpdf = require('node-signpdf').default;
const { readFileSync } = require('fs');
const { addSignaturePlaceholder } = require('node-signpdf/dist/helpers');

const s3 = new AWS.S3();
const bucketName = 'cyclic-weak-pear-pig-tux-sa-east-1';

const app = express();
app.use(express.json());

app.post('/', async (req, res) => {
  try {
    const { pfxFileUrl, pfxPassword } = req.body;

    if (!pfxFileUrl || !pfxPassword) {
      return res.status(400).send('pfx_file_url and pfx_password are required');
    }

    const currentDateTime = new Date().toISOString().replace(/[:.-]/g, '');
    const localFile = `/tmp/pfx_${currentDateTime}`;
    const localFilename = `${localFile}.pfx`;
    const outputFile = `${localFile}.pdf`;

    await downloadFile(pfxFileUrl, localFilename);

    pem.createCertificate({ selfSigned: true }, (err, keys) => {
      if (err) {
        throw err;
      }

      const pdfBuffer = Buffer.from(fs.readFileSync(localFilename));
      const pdfToSign = addSignaturePlaceholder({
        pdfBuffer,
        reason: 'I am the author',
        contactInfo: 'julien@jookies.net',
        name: 'Julien Valentin',
        location: 'France',
      });

      const signerOptions = {
        x: 0,
        y: 0,
        size: 10,
        pageNumber: 0,
        contactInfo: 'julien@jookies.net',
        location: 'France',
        password: pfxPassword,
        name: 'Julien Valentin',
        reason: 'I am the author',
      };

      const signedPdf = signpdf.sign(pdfToSign, keys.clientKey, signerOptions);
      fs.writeFileSync(outputFile, signedPdf);

      const params = {
        Bucket: bucketName,
        Key: outputFile,
        Body: fs.createReadStream(outputFile),
      };

      s3.upload(params, function (err, data) {
        if (err) {
          throw err;
        }
        console.log(`File uploaded successfully. ${data.Location}`);
      });

      res.json({ message: 'Signature generated successfully!', signature: keys.certificate });
    });
  } catch (error) {
    console.error(`Error: ${error}`);
    res.status(500).send(error.message);
  }
});

async function downloadFile(url, localFilename) {
  const response = await axios.get(url, { responseType: 'stream' });
  const writeStream = fs.createWriteStream(localFilename);
  response.data.pipe(writeStream);
  return new Promise((resolve, reject) => {
    writeStream.on('finish', resolve);
    writeStream.on('error', reject);
  });
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
