export const RENTRI_ENV = process.env.RENTRI_ENV || 'SANDBOX';

// Default URLs - OVERRIDE THESE IN RENDER ENV VARS IF NEEDED
const PROD_URL = 'https://rentri.gov.it/api/v1'; 
const TEST_URL = 'https://rentri.gov.it/test/api/v1';

const BASE_URL = process.env.RENTRI_API_URL || (RENTRI_ENV === 'PRODUCTION' ? PROD_URL : TEST_URL);

console.log(`[Config] Running in ${RENTRI_ENV} mode. API Base: ${BASE_URL}`);

export const RENTRI_CONFIG = {
    'global': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_GLOBAL,
        certPath: './certs/certificato.p12'
    },
    'multy': {
        apiBase: BASE_URL,
        apiKey: process.env.RENTRI_API_KEY_MULTY,
        certPath: './certs/multyproget.p12'
    }
};

export type CompanyKey = keyof typeof RENTRI_CONFIG;
