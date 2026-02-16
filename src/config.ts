export const RENTRI_CONFIG = {
    'global': {
        apiBase: 'https://api.rentri.gov.it', // Example
        apiKey: process.env.RENTRI_API_KEY_GLOBAL,
        certPath: './certs/certificato.p12'
    },
    'multy': {
        apiBase: 'https://api.rentri.gov.it',
        apiKey: process.env.RENTRI_API_KEY_MULTY,
        certPath: './certs/multyproget.p12'
    }
};

export type CompanyKey = keyof typeof RENTRI_CONFIG;
