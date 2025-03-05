function allow(forWhom, method, ...args) {

    /*if(fromWhom === "SYSTEM"){
        return true;
    } */
    function checkFromWhom(position) {
        let from = args[position];
        return forWhom === from;
    }

    let from = undefined;
    switch (method) {
        /* public methods */
        case 'listSortedArticles':
            return true;
        case 'getArticleInfo':
            return true;
        case 'listActiveArticles':
            return true;
        case 'getNewArticles':
            return true;
        case 'getChannelInfo':
            return true;
        case 'listChannels':
            return true;
        case 'addAccount':
            return true;
        case 'getUser':
            return true;
        case 'getUserLogs':
            return true;

        /* money related */
        case 'publishArticle': //amount,  authorId, channelID, articleId
        case 'createArticle':
            return checkFromWhom(1)
        case 'boostArticle': //amount, boosterId, channelId, articleId
        case 'boostPost':
            return checkFromWhom(1);
        case 'publishComment': //amount, authorId, channelID, articleId, commentId
        case 'createComment':
        case 'addComment':
            return checkFromWhom(1);
        case 'boostComment':
            return true;
        case 'createAgent':       //agentName, ownerId
            return checkFromWhom(1)
        case 'transferAgentOwnership': //agentId, newOwnerId
            return checkFromWhom(1)
        case 'createChannel': //publicName, firstStakeHolder, channelSettings
            return checkFromWhom(1)
        case 'safeTransfer':    //amount, from, to
            return checkFromWhom(1);
        case 'rewardUserFromGlobalAccount': //accountID, amount, reasonWhy
            return checkFromWhom(0);
        case 'getTotalBalance': //userID
            return checkFromWhom(0);
        case 'loginEvent': //userID
            return checkFromWhom(0);
        case 'validateUser':
            return checkFromWhom(0);


    }
    return false;
}


module.exports = {
    allow
}
