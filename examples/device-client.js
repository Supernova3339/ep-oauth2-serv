#!/usr/bin/env ts-node
"use strict";
/**
 * OAuth 2.0 Device Authorization Grant Demo Client
 *
 * This is a simple demonstration of using the Device Authorization Grant
 * from a command-line application.
 *
 * Usage:
 *   npm run device-demo
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var axios_1 = require("axios");
var open_1 = require("open");
// Configuration
var SERVER_URL = 'http://localhost:3000';
var CLIENT_ID = 'test-client';
var CLIENT_SECRET = 'test-secret';
// Main function
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var deviceAuthResponse, token, userInfo, error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 5, , 6]);
                    console.log('OAuth 2.0 Device Authorization Grant Demo\n');
                    // Step 1: Request device code
                    console.log('Requesting device code...');
                    return [4 /*yield*/, requestDeviceCode()];
                case 1:
                    deviceAuthResponse = _a.sent();
                    console.log('\nDevice authorization initiated!');
                    console.log("User code: ".concat(deviceAuthResponse.user_code));
                    console.log("Verification URL: ".concat(deviceAuthResponse.verification_uri));
                    // Step 2: Open the browser for the user
                    console.log('\nOpening browser for authentication...');
                    return [4 /*yield*/, (0, open_1.default)(deviceAuthResponse.verification_uri_complete)];
                case 2:
                    _a.sent();
                    // Step 3: Poll for token
                    console.log('\nWaiting for authorization...\n');
                    return [4 /*yield*/, pollForToken(deviceAuthResponse.device_code, deviceAuthResponse.interval)];
                case 3:
                    token = _a.sent();
                    // Step 4: Use the token to access the API
                    console.log('Authorization successful!');
                    console.log("Access token: ".concat(token.access_token.substring(0, 10), "..."));
                    console.log("Refresh token: ".concat(token.refresh_token.substring(0, 10), "..."));
                    console.log("Token expires in: ".concat(token.expires_in, " seconds"));
                    console.log("Scopes: ".concat(token.scope));
                    // Get user info
                    console.log('\nFetching user info...');
                    return [4 /*yield*/, getUserInfo(token.access_token)];
                case 4:
                    userInfo = _a.sent();
                    console.log('User info:', userInfo);
                    console.log('\nDevice flow completed successfully!');
                    return [3 /*break*/, 6];
                case 5:
                    error_1 = _a.sent();
                    if (error_1 instanceof Error) {
                        console.error('Error:', error_1.message);
                        if (axios_1.default.isAxiosError(error_1) && error_1.response) {
                            console.error('Server response:', error_1.response.data);
                        }
                    }
                    else {
                        console.error('Unknown error:', error_1);
                    }
                    process.exit(1);
                    return [3 /*break*/, 6];
                case 6: return [2 /*return*/];
            }
        });
    });
}
// Request device code
function requestDeviceCode() {
    return __awaiter(this, void 0, void 0, function () {
        var response;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, axios_1.default.post("".concat(SERVER_URL, "/oauth/device"), {
                        client_id: CLIENT_ID,
                        scope: 'profile email'
                    })];
                case 1:
                    response = _a.sent();
                    return [2 /*return*/, response.data];
            }
        });
    });
}
// Poll for token
function pollForToken(deviceCode, interval) {
    return __awaiter(this, void 0, void 0, function () {
        var pollInterval, response, error_2, errorData;
        var _a;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    pollInterval = (interval || 5) * 1000;
                    _b.label = 1;
                case 1:
                    if (!true) return [3 /*break*/, 7];
                    _b.label = 2;
                case 2:
                    _b.trys.push([2, 4, , 5]);
                    return [4 /*yield*/, axios_1.default.post("".concat(SERVER_URL, "/oauth/token"), {
                            client_id: CLIENT_ID,
                            client_secret: CLIENT_SECRET,
                            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                            device_code: deviceCode
                        })];
                case 3:
                    response = _b.sent();
                    // If we get here, we have a token
                    return [2 /*return*/, response.data];
                case 4:
                    error_2 = _b.sent();
                    if (axios_1.default.isAxiosError(error_2) && ((_a = error_2.response) === null || _a === void 0 ? void 0 : _a.data)) {
                        errorData = error_2.response.data;
                        // Handle error codes according to RFC 8628
                        switch (errorData.error) {
                            case 'authorization_pending':
                                // This is expected, user hasn't approved yet
                                process.stdout.write('.');
                                break;
                            case 'slow_down':
                                // We're polling too fast, increase the interval
                                process.stdout.write('s');
                                pollInterval += 5000;
                                break;
                            case 'expired_token':
                                throw new Error('The device code has expired. Please try again.');
                            case 'access_denied':
                                throw new Error('The user denied the authorization request.');
                            default:
                                throw new Error("Authentication error: ".concat(errorData.error, ": ").concat(errorData.error_description || ''));
                        }
                    }
                    else {
                        // Unexpected error
                        throw error_2;
                    }
                    return [3 /*break*/, 5];
                case 5: 
                // Wait for the poll interval
                return [4 /*yield*/, new Promise(function (resolve) { return setTimeout(resolve, pollInterval); })];
                case 6:
                    // Wait for the poll interval
                    _b.sent();
                    return [3 /*break*/, 1];
                case 7: return [2 /*return*/];
            }
        });
    });
}
// Get user info
function getUserInfo(accessToken) {
    return __awaiter(this, void 0, void 0, function () {
        var response;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, axios_1.default.get("".concat(SERVER_URL, "/oauth/userinfo"), {
                        headers: {
                            'Authorization': "Bearer ".concat(accessToken)
                        }
                    })];
                case 1:
                    response = _a.sent();
                    return [2 /*return*/, response.data];
            }
        });
    });
}
// Run the main function
main().catch(function (error) {
    console.error('Unhandled error:', error);
    process.exit(1);
});
