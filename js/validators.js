const USERNAME_REGEX = /^(?=.{6,50}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$/;
const TOTP_REGEX = /^\d{6,8}$/;

const CORE_VALIDATOR = {
    /**
     * @param {string} username
     * @returns {string | null}
     */
    USERNAME(username) {
        if (!username) {
            return 'Username is required.';
        }

        if (!USERNAME_REGEX.test(username)) {
            return 'Username needs to contain from 6 to 50 characters.';
        }

        return null;
    },

    /**
     * @param {string} password
     * @returns {string | null}
     */
    PASSWORD(password) {
        if (!password || typeof password !== 'string') {
            return 'Password is required.';
        }

        if (password.length < 12) {
            return 'Password needs to contain at least 12 characters.';
        }

        if (password.length > 4096) {
            return 'Password needs to contain at most 4096 characters.';
        }

        return null;
    },

    /**
     * @param {string} totp
     * @returns {string | null}
     */
    TOTP(totp) {
        if (!totp || typeof totp !== 'string') {
            return 'TOTP is required.';
        }

        if (!TOTP_REGEX.test(totp)) {
            return 'TOTP needs to contain 8 digits.';
        }

        return null;
    }

};

export { CORE_VALIDATOR };
