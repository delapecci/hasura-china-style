const CHINESE_MOBILE_REGEXP = /^1[3456789]\d{9}$/;

/**
 * 检查中国大陆手机号码格式
 * @param {string} mobile 中国内地手机号码
 */
function checkMobileOfChinaMainland (mobile) {
  return CHINESE_MOBILE_REGEXP.test(phone);
}

module.exports = {
  checkMobileOfChinaMainland
}
