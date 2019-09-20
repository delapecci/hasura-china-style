/**
 * multer storage for S3
 */

const uuidv4 = require('uuid/v4');
const multer = require('multer');
const multerS3 = require('multer-s3');
const AWS = require('aws-sdk');
const mime = require('mime-types');

const {
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_ENDPOINT,
  S3_BUCKET,
} = require('../config');

const s3  = new AWS.S3({
  accessKeyId: S3_ACCESS_KEY_ID,
  secretAccessKey: S3_SECRET_ACCESS_KEY,
  endpoint: S3_ENDPOINT,
  s3ForcePathStyle: true,
  signatureVersion: 'v4',
});

const storage = multerS3({
  s3: s3,
  bucket: S3_BUCKET,
  metadata: (req, file, cb) => {
    cb(null, {
      originalname: file.originalname,
    });
  },
  contentType: function (req, file, cb) {
    cb(null, file.mimetype);
  },
  key: function (req, file, cb) {

    // generate unique file names to be saved on the server
    const uuid = uuidv4();
    const extension = mime.extension(file.mimetype);
    const key = `${req.key_prefix}${uuid}.${extension}`;

    req.saved_files.push({
      originalname: file.originalname,
      mimetype: file.mimetype,
      encoding: file.encoding,
      key,
      extension,
    });

    cb(null, key);
  },
});

/**
 * Middleware before uploading
 * @param {Request} req HTTP Request (Express)
 * @param {Response} res HTTP Response (Express)
 * @param {Function} next Next middleware
 */
const preUpload = (req, res, next) => {

  // path to where the file will be uploaded to
  try {
    req.key_prefix = req.headers['x-path'].replace(/^\/+/g, '');
  } catch (e) {
    return next(Boom.badImplementation('x-path header incorrect'));
  }

  next();
};

/**
 * Get object from storage and make response to client
 * @param {Request} req HTTP Request (Express)
 * @param {Response} res HTTP Response (Express)
 * @param {Function} next Next middleware
 */
const getObject = async (req, res, next) => {
  const key = `${req.params[0]}`;
  const params = {
    Bucket: S3_BUCKET,
    Key: key,
  };

  s3.headObject(params, function (err, data) {

    if (err) {
      console.error(err);
      if (err.code === 'NotFound') {
        return next(Boom.notFound());
      }
      return next(Boom.badImplementation('Unable to retreive file'));
    }

    const stream = s3.getObject(params).createReadStream();

    // forward errors
    stream.on('error', function error(err) {
      console.error(err);
      return next(Boom.badImplementation());
    });

    //Add the content type to the response (it's not propagated from the S3 SDK)
    res.set('Content-Type', data.ContentType);
    res.set('Content-Length', data.ContentLength);
    res.set('Last-Modified', data.LastModified);
    res.set('Content-Disposition', `inline; filename="${data.Metadata.originalname}"`);
    res.set('Cache-Control', 'public, max-age=31557600');
    res.set('ETag', data.ETag);

    // stream.on('end', () => {
    //     console.log('Served by Amazon S3: ' + key);
    // });

    //Pipe the s3 object to the response
    stream.pipe(res);
  });
}

module.exports = {
  storage,
  preUpload,
  getObject
};
