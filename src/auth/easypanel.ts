import axios from 'axios';
import { EASYPANEL_URL } from '../config';
import { EasypanelUser, LoginResponse } from '../types';

/**
 * Validate Easypanel credentials
 *
 * @param email User email
 * @param password User password
 * @param code Two-factor authentication code (optional)
 * @returns Login response object
 */
export async function validateEasypanelCredentials(
    email: string,
    password: string,
    code?: string
): Promise<LoginResponse> {
    try {
        // Create the request payload
        const payload: any = {
            json: {
                email,
                password,
            }
        };

        // Add 2FA code if provided
        if (code) {
            payload.json.code = code;
        }

        // Call Easypanel API to validate credentials
        const response = await axios.post(
            `${EASYPANEL_URL}/api/trpc/auth.login`,
            payload,
            {
                headers: {
                    'Content-Type': 'application/json',
                }
            }
        );

        // Check for 2FA requirement
        if (response.status === 200 &&
            response.data?.result?.data?.json?.twoFactorEnabled === true) {
            return {
                success: false,
                twoFactorRequired: true
            };
        }

        // Check if the login was successful
        if (response.status === 200 &&
            response.data?.result?.data?.json?.token) {

            // Get the token from the response
            const token = response.data.result.data.json.token;

            try {
                // Get the user information using the token
                const user = await getUserInfo(token);

                if (user) {
                    return {
                        success: true,
                        user,
                        token
                    };
                }
            } catch (userError) {
                console.error('Error fetching user data from Easypanel:', userError);
                return {
                    success: false,
                    error: 'Unable to fetch user information'
                };
            }
        }

        return {
            success: false,
            error: 'Invalid credentials'
        };
    } catch (error) {
        // Handle error responses more gracefully
        if (axios.isAxiosError(error) && error.response) {
            console.error('Easypanel login error:', error.response.status, error.response.data);

            // Extract user-friendly error message from Easypanel response
            let errorMessage = 'Authentication failed';

            try {
                // Try to extract error message from various possible structures
                if (error.response.data?.error?.json?.message) {
                    errorMessage = error.response.data.error.json.message;
                } else if (error.response.data?.message) {
                    errorMessage = error.response.data.message;
                } else if (typeof error.response.data === 'string') {
                    errorMessage = error.response.data;
                }

                // Handle specific error codes or messages
                if (errorMessage.includes('Invalid Code')) {
                    errorMessage = 'Invalid verification code. Please try again.';
                } else if (errorMessage.includes('expired')) {
                    errorMessage = 'Verification code has expired. Please request a new one.';
                }
            } catch (parseError) {
                console.error('Error parsing error response:', parseError);
            }

            return {
                success: false,
                error: errorMessage
            };
        } else {
            console.error('Error validating Easypanel credentials:', error);

            return {
                success: false,
                error: 'Authentication service unavailable'
            };
        }
    }
}

/**
 * Get user information using a token
 *
 * @param token Authentication token
 * @returns User object or null
 */
export async function getUserInfo(token: string): Promise<EasypanelUser | null> {
    try {
        const userResponse = await axios.get(`${EASYPANEL_URL}/api/trpc/auth.getUser`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            }
        });

        // Check if we got a valid user response
        if (userResponse.status === 200 &&
            userResponse.data?.result?.data?.json) {

            // Verify we actually got a user ID to confirm success
            const userData = userResponse.data.result.data.json;
            if (userData && userData.id) {
                return userData;
            }
        }

        return null;
    } catch (error) {
        console.error('Error fetching user info:', error);
        return null;
    }
}

/**
 * List all users (admin only)
 *
 * @param token Authentication token
 * @returns Array of users or null
 */
export async function listUsers(token: string): Promise<EasypanelUser[] | null> {
    try {
        const response = await axios.get(`${EASYPANEL_URL}/api/trpc/users.listUsers`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            }
        });

        if (response.status === 200 &&
            response.data?.result?.data?.json?.users) {
            // Return the users array from the API response
            return response.data.result.data.json.users;
        }

        return null;
    } catch (error) {
        console.error('Error listing users:', error);
        return null;
    }
}

/**
 * Get a specific user by ID
 *
 * @param token Authentication token
 * @param userId User ID to find
 * @returns User object or null
 */
export async function getUserById(token: string, userId: string): Promise<EasypanelUser | null> {
    try {
        const users = await listUsers(token);

        if (users && Array.isArray(users)) {
            return users.find(user => user.id === userId) || null;
        }

        return null;
    } catch (error) {
        console.error('Error getting user by ID:', error);
        return null;
    }
}