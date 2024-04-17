
using SecreteKeysTop;

//var result = PasswordRfc2898.GeneratePassword("pass");

var secret = CripAES.GenerateSecretKey();

CripAES.Criptograph("scnpscdsvsdvsdv", Convert.FromBase64String(secret));
CripAES.Discriptograph(Convert.FromBase64String(secret));

var aaa = ";";

