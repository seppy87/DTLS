#include "Policy.hpp"

DTLS::Policy::Policy(DTLSVersion minimalVersion)
{
	switch (minimalVersion) {
	case DTLSVersion::DTLS_ANY:
	case DTLSVersion::DTLS_1_0:
		this->dtls10_enabled = true;
	case DTLSVersion::DTLS_1_2:
		this->dtls12_enabled = true;
	case DTLSVersion::DTLS_1_3:
		this->dtls13_enabled = true; // I know it is not implemented but in future!
		break;
	default:
		std::cerr << "THIS SHOULD NOT HAPPEN!\n";
		break;
	}
}

bool DTLS::Policy::removeItemAllowedOption(DTLSAllowedOption option, const std::string& key)
{
	switch (option) {
	case DTLSAllowedOption::DTLS_ALLOWED_CIPHERS: {
		for (auto iter = this->allowedCiphersVec.begin(); iter != allowedCiphersVec.end(); iter++) {
			if (*iter == key) {
				iter = this->allowedCiphersVec.erase(iter);
				return true;
			}
		}
		return false;
	}
	break;
	case DTLSAllowedOption::DTLS_ALLOWED_KEY_EXCHANGE_METHODS:
	{
		for (auto iter = this->allowedKeyExchangeMethodsVec.begin(); iter != allowedKeyExchangeMethodsVec.end(); iter++) {
			if (*iter == key) {
				iter = this->allowedKeyExchangeMethodsVec.erase(iter);
				return true;
			}
		}
		return false;
	}
	break;
	case DTLSAllowedOption::DTLS_ALLOWED_MACS:
	{
		for (auto iter = this->allowedMacsVec.begin(); iter != allowedMacsVec.end(); iter++) {
			if (*iter == key) {
				iter = this->allowedMacsVec.erase(iter);
				return true;
			}
		}
		return false;
	}
	break;
	case DTLSAllowedOption::DTLS_ALLOWED_SIGNATURE_HASHES:
	{
		for (auto iter = this->allowedSignatureHashesVec.begin(); iter != allowedSignatureHashesVec.end(); iter++) {
			if (*iter == key) {
				iter = this->allowedSignatureHashesVec.erase(iter);
				return true;
			}
		}
		return false;
	}
	break;
	case DTLSAllowedOption::DTLS_ALLOWED_SIGNATURE_METHODS:
	{
		for (auto iter = this->allowedSignatureMethodsVec.begin(); iter != allowedSignatureMethodsVec.end(); iter++) {
			if (*iter == key) {
				iter = this->allowedSignatureMethodsVec.erase(iter);
				return true;
			}
			
		}
		return false;
	}
	break;
	default:
		return false;
	}
	//return false;
}

bool DTLS::Policy::overrideAllowedOption(DTLSAllowedOption option, std::vector<std::string>& vector)
{
	switch (option) {
	case DTLSAllowedOption::DTLS_ALLOWED_CIPHERS:
		this->allowedCiphersVec = std::move(vector);
		return true;
	case DTLSAllowedOption::DTLS_ALLOWED_KEY_EXCHANGE_METHODS:
		this->allowedKeyExchangeMethodsVec = std::move(vector);
		return true;
	case DTLSAllowedOption::DTLS_ALLOWED_MACS:
		this->allowedMacsVec = std::move(vector);
		return true;
	case DTLSAllowedOption::DTLS_ALLOWED_SIGNATURE_HASHES:
		this->allowedSignatureHashesVec = std::move(vector);
		return true;
	case DTLSAllowedOption::DTLS_ALLOWED_SIGNATURE_METHODS:
		this->allowedSignatureMethodsVec = std::move(vector);
		return true;
	default:
		std::cerr << "This should not happen. overrideAllowedOption\n";
		return false;
	}
	return false;
}
