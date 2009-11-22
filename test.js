var crypto=require("./crypto");
var sys=require("sys");
var posix=require('posix');

// Test HMAC
var h1 = (new crypto.Hmac).init("sha1", "Node").update("some data").update("to hmac").digest("hex");
sys.puts(h1);
sys.puts(h1==='19fd6e1ba73d9ed2224dd5094a71babe85d9a892');

// Test hashing
var a0 = (new crypto.Hash).init("sha1").update("Test123").digest("hex");
var a1 = (new crypto.Hash).init("md5").update("Test123").digest("binary");
var a2=  (new crypto.Hash).init("sha256").update("Test123").digest("base64");
var a3 = (new crypto.Hash).init("sha512").update("Test123").digest(); // binary

sys.puts((new crypto.Hash).init("ripemd160").update("Nobody inspects the spammish repetition").digest("hex"));

// Test multiple updates to same hash
var h1 = (new crypto.Hash).init("sha1").update("Test123").digest("hex");
var h2 = (new crypto.Hash).init("sha1").update("Test").update("123").digest("hex");
sys.puts(h1===h2);


// Load our public and private keys
var keyPem = posix.cat("test_key.pem").wait();
var certPem = posix.cat("test_cert.pem").wait();

// Test signing and verifying
var s1 = (new crypto.Sign).init("RSA-SHA1").update("Test123").sign(keyPem, "base64");
sys.puts((new crypto.Verify).init("RSA-SHA1").update("Test").update("123").verify(certPem, s1, "base64"));

var s2 = (new crypto.Sign).init("RSA-SHA256").update("Test123").sign(keyPem); // binary
sys.puts((new crypto.Verify).init("RSA-SHA256").update("Test").update("123").verify(certPem, s2)); // binary


