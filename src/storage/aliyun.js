/**
 * multer storage for ALIYUN OSS
 */

const uuidv4 = require('uuid/v4');
const multer = require('multer');
const OSS = require('ali-oss');
const mime = require('mime-types');

const {
  ALIYUN_ACCESS_KEY_ID,
  ALIYUN_SECRET_ACCESS_KEY,
  ALIYUN_ENDPOINT,
  ALIYUN_BUCKET,
  ALIYUN_REGION,
  ALIYUN_TIMEOUT,
} = require('../config');

const ossConfig = {
  endpoint: ALIYUN_ENDPOINT,
  region: ALIYUN_REGION,
  accessKeyId: ALIYUN_ACCESS_KEY_ID,
  accessKeySecret: ALIYUN_SECRET_ACCESS_KEY,
  bucket: ALIYUN_BUCKET,
  timeout: ALIYUN_TIMEOUT
};
const ossClient = new OSS(ossConfig);

const storageConfig = {
  config: ossConfig,
  client: ossClient,
  filename: (req, file, cb) => {
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
  }
};


class AliYunOssStorage {
	constructor(opts) {
		this.client = opts.client || new OSS(opts.config);
		this.getFilename = opts.filename || getFilename;
	}

	_handleFile(req, file, cb) {
		if (!this.client) {
			console.error('oss client undefined');
			return cb({message: 'oss client undefined'});
		}
		this.getFilename(req, file, (err, filename) => {
			if (err) return cb(err);
			this.client.putStream(filename, file.stream).then(
				result => {
					return cb(null, {
						filename: result.name,
						url     : result.url
					});
				}
			).catch(err => {
				return cb(err);
			});
		});
	}

	_removeFile(req, file, cb) {
		if (!this.client) {
			console.error('oss client undefined');
			return cb({message: 'oss client undefined'});
		}
		this.client.delete(file.filename).then(
			result => {
				return cb(null, result);
			}
		).catch(err => {
			return cb(err);
		});
	}
}

const storage = new AliYunOssStorage(storageConfig);

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

  const result = await ossClient.getStream(key);
  result.stream.pipe(res);
};

module.exports = {
  storage,
  preUpload,
  getObject
};
