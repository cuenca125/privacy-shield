# Keystore

The release keystore file (release.keystore) is NOT committed to version control.

To generate a keystore for local builds:
  keytool -genkey -v -keystore release.keystore -alias privacyshield -keyalg RSA -keysize 2048 -validity 10000

For CI/CD builds, set these environment variables:
  KEYSTORE_PATH — absolute path to the keystore file
  KEYSTORE_PASSWORD — keystore password
  KEY_ALIAS — key alias (default: privacyshield)
  KEY_PASSWORD — key password
