const express = require('express');
const axios = require('axios');
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

const app = express();
app.use(express.json());

app.post('/', async (req, res) => {
    try {
        const { pfx_file_url, pfx_password } = req.body;

        if (!pfx_file_url) {
            return res.status(400).send('pfx_file_url is required');
        }

        if (!pfx_password) {
            return res.status(400).send('pfx_password is required');
        }

        const response = await axios.post('https://leomarz.pythonanywhere.com/', {
            pfx_file_url,
            pfx_password
        });

        const { signature } = response.data;

        const params = {
            Body: JSON.stringify(signature),
            Bucket: "cyclic-weak-pear-pig-tux-sa-east-1",
            Key: `signatures/${signature.id}.json`,
        };

        await s3.putObject(params).promise();

        res.json({ message: 'Signature generated and stored successfully!', signature });
    } catch (error) {
        console.error(`Error: ${error}`);
        res.status(500).send(error.message);
    }
});

app.listen(3000, () => {
    console.log('Server started on port 3000');
});
