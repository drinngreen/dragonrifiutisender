// FORCE PRODUCTION DEFAULT
export const RENTRI_ENV = process.env.RENTRI_ENV || 'PRODUCTION';

// CORRECTED PROD URL FOR FORMULARI (FIR)
const PROD_URL = 'https://api.rentri.gov.it/formulari/v1.0'; 
const TEST_URL = 'https://rentri.gov.it/test/api/v1';

// Use PROD_URL by default unless env is explicitly SANDBOX
const BASE_URL = process.env.RENTRI_API_URL || (RENTRI_ENV === 'SANDBOX' ? TEST_URL : PROD_URL);

console.log(`[Config] Running in ${RENTRI_ENV} mode. API Base: ${BASE_URL}`);

export const RENTRI_CONFIG = {
    'global': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_GLOBAL,
        certPath: process.env.RENTRI_CERT_PATH_GLOBAL || './certs/certificato.p12'
    },
    'multy': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_MULTY,
        certPath: process.env.RENTRI_CERT_PATH_MULTY || './certs/multyproget.p12'
    },
    'niyol': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_NIYOL,
        certPath: process.env.RENTRI_CERT_PATH_NIYOL || './certs/niyol.p12'
    }
};

export type CompanyKey = keyof typeof RENTRI_CONFIG;
