
const REFRESH_TOKEN_COOKIE_NAME = 'rfh';
const SIGNATURE_ACCESS_TOKEN_COOKIE_NAME = 'sig';
const PAYLOAD_ACCESS_TOKEN_COOKIE_NAME = 'pld';

const PAGES = {
    get LOGIN() {
       return window.location.origin + '/web-app' + '/pages/login'; // @fixme remove web-app
    },
    get MAIN() {
        return window.location.origin + '/web-app' + '/pages/main';  // @fixme remove web-app
    },
    get REGISTER() {
        return window.location.origin + '/web-app' + '/pages/register';  // @fixme remove web-app
    },
    get FORGOT_PASSWORD() {
        return window.location.origin + '/web-app' + '/pages/forgot/password';  // @fixme remove web-app
    }
};
Object.freeze(PAGES);

const SYMBOLS = {
    WINDOW_RECAPTCHA_TOKEN: Symbol('WINDOW_RECAPTCHA_TOKEN')
};
Object.freeze(SYMBOLS);

export { REFRESH_TOKEN_COOKIE_NAME, SIGNATURE_ACCESS_TOKEN_COOKIE_NAME, PAYLOAD_ACCESS_TOKEN_COOKIE_NAME, PAGES, SYMBOLS };
