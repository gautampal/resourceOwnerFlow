var crypt=require('./crypto.js');

console.log(crypt.encrypt(process.argv[2], process.env.CONF_KEY));
