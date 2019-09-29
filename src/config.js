exports.AUTH_ACTIVE = process.env.AUTH_ACTIVE ? process.env.AUTH_ACTIVE === 'true' : true;
exports.STORAGE_ACTIVE = process.env.STORAGE_ACTIVE ? process.env.STORAGE_ACTIVE === 'true' : true;
exports.USER_FIELDS = process.env.USER_FIELDS ? process.env.USER_FIELDS.split(',') : [];
exports.USER_MANAGEMENT_DATABASE_SCHEMA_NAME = process.env.USER_MANAGEMENT_DATABASE_SCHEMA_NAME || 'public';
exports.USER_REGISTRATION_AUTO_ACTIVE = process.env.USER_REGISTRATION_AUTO_ACTIVE ? process.env.USER_REGISTRATION_AUTO_ACTIVE === 'true' : false;
exports.HASURA_GRAPHQL_ENDPOINT = process.env.HASURA_GRAPHQL_ENDPOINT || 'http://graphql-engine:8080/v1/graphql';
exports.HASURA_GRAPHQL_ADMIN_SECRET = process.env.HASURA_GRAPHQL_ADMIN_SECRET || 'Acce55Gr@nted';
exports.HASURA_GRAPHQL_JWT_SECRET = process.env.HASURA_GRAPHQL_JWT_SECRET ? JSON.parse(process.env.HASURA_GRAPHQL_JWT_SECRET) : {'type':'HS256', 'key': 'W0+jiu+shi+zhong+xin+xi+huan_Hasura+_1_2_3'};
exports.REFETCH_TOKEN_EXPIRES = process.env.REFETCH_TOKEN_EXPIRES || (60*24*30); // expire after 30 days
exports.JWT_TOKEN_EXPIRES = process.env.JWT_TOKEN_EXPIRES || 60; // expire after 15 minutes

exports.SYSTEM_NAME = process.env.SYSTEM_NAME || 'Hasura China';

exports.STORAGE_PROVIDER = process.env.STORAGE_PROVIDER || 'qiniu';

exports.S3_ACCESS_KEY_ID = process.env.S3_ACCESS_KEY_ID || '';
exports.S3_SECRET_ACCESS_KEY = process.env.S3_SECRET_ACCESS_KEY || '';
exports.S3_ENDPOINT = process.env.S3_ENDPOINT || '';
exports.S3_BUCKET = process.env.S3_BUCKET || '';

exports.ALIYUN_ACCESS_KEY_ID = process.env.ALIYUN_ACCESS_KEY_ID || 'SKwSj3bcQzH8F3Yg';
exports.ALIYUN_SECRET_ACCESS_KEY = process.env.ALIYUN_SECRET_ACCESS_KEY || '';
exports.ALIYUN_ENDPOINT = process.env.ALIYUN_ENDPOINT || 'oss-cn-qingdao.aliyuncs.com';
exports.ALIYUN_BUCKET = process.env.ALIYUN_BUCKET || 'qh-dev';
exports.ALIYUN_REGION = process.env.ALIYUN_REGION || 'oss-cn-hangzhou';
exports.ALIYUN_TIMEOUT = process.ALIYUN_OSS_TIMEOUT || 120; // 120s

exports.QINIU_ACCESS_KEY_ID = process.env.QINIU_ACCESS_KEY_ID || '09SdFcSDX4x5yjOQkbNjgspa6RiWMYLLYNBcq7he';
exports.QINIU_SECRET_ACCESS_KEY = process.env.QINIU_SECRET_ACCESS_KEY || '';
exports.QINIU_ENDPOINT = process.env.QINIU_ENDPOINT || 's3-cn-east-1.qiniucs.com';
exports.QINIU_BUCKET = process.env.QINIU_BUCKET || 'pj-images';
exports.QINIU_REGION = process.env.QINIU_REGION || 'qiniu.zone.Zone_z0';
exports.QINIU_TIMEOUT = process.QINIU_TIMEOUT || 120; // 120s
