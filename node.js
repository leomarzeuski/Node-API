    const express = require('express');
const axios = require('axios');
const forge = require('node-forge');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const AWS = require('aws-sdk');

const s3 = new AWS.S3();
const bucketName = 'cyclic-weak-pear-pig-tux-sa-east-1';

const app = express();
app.use(express.json());

app.post('/', async (req, res) => {
    try {
        const { pfxFileUrl, pfxPassword } = req.body;

        if (!pfxFileUrl || !pfxPassword) {
            return res.status(400).send('pfxFileUrl and pfxPassword are required');
        }

        const pfxResponse = await axios.get(pfxFileUrl, { responseType: 'arraybuffer' });
        const pfxBuffer = Buffer.from(pfxResponse.data, 'binary');

        const pfxAsn1 = forge.asn1.fromDer(forge.util.binary.raw.encode(pfxBuffer));
        const pfxObj = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, pfxPassword);

        const keyObj = pfxObj.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag }).friendlyName[0];
        const certObj = pfxObj.getBags({ bagType: forge.pki.oids.certBag }).friendlyName[0];

        const privateKey = forge.pki.privateKeyToPem(keyObj.key);
        const certificate = forge.pki.certificateToPem(certObj.cert);

        const pdfDoc = await PDFDocument.create();
        const timesRomanFont = await pdfDoc.embedFont(StandardFonts.TimesRoman);

        const page = pdfDoc.addPage();
        const { width, height } = page.getSize();
        const fontSize = 30;
        page.drawText('This is a new PDF document', {
            x: 50,
            y: height - 4 * fontSize,
            size: fontSize,
            font: timesRomanFont,
            color: rgb(0, 0, 0),
        });

        const pdfBytes = await pdfDoc.save();

        const params = {
            Bucket: bucketName,
            Key: 'signedDocument.pdf',
            Body: pdfBytes,
        };

        s3.upload(params, function(err, data) {
            if (err) {
                throw err;
            }
            console.log(`File uploaded successfully. ${data.Location}`);
        });

        res.json({
            message: 'Signature generated successfully!',
            signature: {
                id: certObj.cert.serialNumber,
                nameCpf: certObj.cert.subject.getField('CN').value,
                type: certObj.cert.subject.getField('OU').value,
                bir: certObj.cert.subject.getField('O').value,
                address: certObj.cert.subject.getField('L').value,
                signatureText: certObj.cert.subject.getField('ST').value,
            },
        });
    } catch (error) {
        console.error(`Error: ${error}`);
        res.status(500).send(error.toString());
    }
});

app.listen(3000, () => console.log('Server started on port 3000'));
