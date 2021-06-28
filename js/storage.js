class Storage {
    /**
     * @param {AccountDTO} account
     */
    storeAccount(account) {
        localStorage.setItem('acc',JSON.stringify(account));
    }

    /**
     * @returns {AccountDTO | null}
     */
    retrieveAccount() {
        const account = localStorage.getItem('acc');
        if (account != null) {
            return JSON.parse(account);
        }
        return null;
    }
}

const STORAGE = new Storage();
export { STORAGE };
