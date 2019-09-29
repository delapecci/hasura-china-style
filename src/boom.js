const Boom = require('boom');

module.exports = {
  wrapError: (statusCode, code, message) => {
    const error = new Error();
    error.code = code;
    error.message = message;
    const boom = Boom.boomify(error, { statusCode, override: false } );
    // boom.reformat();
    boom.output.payload.errorCode = code;
    return boom;
  }
}
