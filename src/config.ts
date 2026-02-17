// FORCE PRODUCTION DEFAULT
export const RENTRI_ENV = process.env.RENTRI_ENV || 'PRODUCTION';

const PROD_URL = 'https://api.rentri.gov.it/formulari/v1.0'; 
const TEST_URL = 'https://rentri.gov.it/test/api/v1';

const BASE_URL = process.env.RENTRI_API_URL || (RENTRI_ENV === 'SANDBOX' ? TEST_URL : PROD_URL);

// Calculate correct Audience based on environment
// Prod: "rentrigov.api"
// Test/Demo: "rentrigov.demo.api"
export const RENTRI_AUDIENCE = (RENTRI_ENV === 'SANDBOX' || BASE_URL.includes('demo') || BASE_URL.includes('test')) 
    ? 'rentrigov.demo.api' 
    : 'rentrigov.api';

console.log(`[Config] Running in ${RENTRI_ENV} mode. API Base: ${BASE_URL}. Audience: ${RENTRI_AUDIENCE}`);

export const RENTRI_CONFIG = {
    'global': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_GLOBAL,
        certPath: process.env.RENTRI_CERT_PATH_GLOBAL || './certs/certificato.p12',
        issuer: process.env.RENTRI_ISSUER_GLOBAL || '08934760961' // CF/P.IVA from Certificate Subject
    },
    'multy': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_MULTY,
        certPath: process.env.RENTRI_CERT_PATH_MULTY || './certs/multyproget.p12',
        issuer: process.env.RENTRI_ISSUER_MULTY || '12347770013' // CF/P.IVA from Certificate Subject
    },
    'niyol': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_NIYOL,
        certPath: process.env.RENTRI_CERT_PATH_NIYOL || './certs/niyol.p12',
        issuer: process.env.RENTRI_ISSUER_NIYOL || '09879800010' // CF/P.IVA from Certificate Subject
    }
};

export type CompanyKey = keyof typeof RENTRI_CONFIG;
