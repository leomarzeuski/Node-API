const express = require('express');
const axios = require('axios');
const fs = require('fs');
const AWS = require('aws-sdk');
const forge = require('node-forge');
const signpdf = require('node-signpdf').default;
const { readFileSync } = require('fs');
const { addSignaturePlaceholder } = require('node-signpdf/dist/helpers');

const s3 = new AWS.S3();
const bucketName = 'cyclic-pleasant-erin-coveralls-sa-east-1';

const app = express();

app.use(express.json());

app.post('/', async (req, res) => {
  try {
    const pfxFileUrl = req.body.pfx_file_url;
    const pfxPassword = req.body.pfx_password;

    if (!pfxFileUrl) {
      return res.status(400).send('pfx_file_url is required');
    }

    if (!pfxPassword) {
      return res.status(400).send('pfx_password is required');
    }

    const localFile = `/tmp/pfx_${Date.now()}`;

    const localFilename = await transformPfxInPdf(pfxFileUrl, localFile);

    const outputFilename = `${localFile}.pdf`;

    const signature = await generateKeyAndSign(localFilename, pfxPassword, outputFilename);

    return res.status(200).json({ message: 'Signature generated successfully!', signature });
  } catch (e) {
    console.error(`Error: ${e}`);
    return res.status(500).send(e.toString());
  }
});

async function transformPfxInPdf(pfxFileUrl, localFile) {
  const localFilename = `${localFile}.pfx`;
  await downloadFile(pfxFileUrl, localFilename);
  return localFilename;
}

async function downloadFile(url, localFilename) {
  const response = await axios.get(url, { responseType: 'arraybuffer' });
  await s3.putObject({ Body: response.data, Bucket: bucketName, Key: localFilename }).promise();
}

async function loadCertificateAndKey(pfxPath, password) {
  const pfxFile = await s3.getObject({ Bucket: bucketName, Key: pfxPath }).promise();
  const pfxDer = forge.util.decode64(pfxFile.Body.toString('base64'));
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const pfxObj = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, password);

  const keyBags = pfxObj.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag }).friendlyName;
  const certBags = pfxObj.getBags({ bagType: forge.pki.oids.certBag }).friendlyName;

  if (!keyBags || !certBags) {
    throw new Error('Failed to get key or certificate bags');
  }

  const keyObj = keyBags[0];
  const certObj = certBags[0];

  return { key: forge.pki.privateKeyToPem(keyObj.key), cert: forge.pki.certificateToPem(certObj.cert) };
}

async function generateKeyAndSign(pfxPath, password, outputFilename) {
  const { key, cert } = await loadCertificateAndKey(pfxPath, password);

  const pdfBuffer = Buffer.from('<pdf content>', 'base64');
  const pdfToSign = addSignaturePlaceholder({
    pdfBuffer,
    reason: 'I am the author',
    contactInfo: 'julien@jookies.net',
    name: 'Julien TA',
    location: 'France',
  });

  const signer = signpdf.createSigner({
    key: readFileSync(key),
    cert: readFileSync(cert),
  });

  const signedPdf = signer.sign(pdfToSign, Buffer.from(key));

  await s3.putObject({ Body: signedPdf, Bucket: bucketName, Key: outputFilename }).promise();

  const signature = {
    id: cert.serialNumber,
    'name/cpf': cert.subject.getField('CN').value,
    type: cert.subject.getField('OU').value,
    bir: cert.subject.getField('O').value,
    address: cert.subject.getField('L').value,
    signature_text: cert.subject.getField('ST').value,
  };

  return signature;
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
