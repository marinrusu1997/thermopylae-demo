
class ApiError extends Error {
    code;

    /**
     * @param {string} code
     * @param {string} message
     */
    constructor(code, message) {
        super(message);
        Error.captureStackTrace(this, ApiError);

        this.code = code;
    }
}

export { ApiError }
