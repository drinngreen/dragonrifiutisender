import axios from 'axios';
import { CompanyKey } from '../config';

// Simple in-memory cache for tokens
const tokenCache: Record<string, { token: string, expires: number }> = {};

export async function getAuthHeaders(company: CompanyKey) {
    // Check cache
    const now = Date.now();
    if (tokenCache[company] && tokenCache[company].expires > now) {
        return {
            'Authorization': `Bearer ${tokenCache[company].token}`,
            'Content-Type': 'application/xml'
        };
    }

    // TODO: Implement Real OAuth2 / Client Cert Logic here
    // This is a placeholder that simulates getting a token
    console.log(`[Auth] Authenticating for ${company}...`);
    
    const mockToken = `mock_token_${company}_${now}`;
    tokenCache[company] = {
        token: mockToken,
        expires: now + 3600 * 1000 // 1 hour
    };

    return {
        'Authorization': `Bearer ${mockToken}`,
        'Content-Type': 'application/xml'
    };
}
