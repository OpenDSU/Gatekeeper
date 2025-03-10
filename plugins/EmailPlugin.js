const sgMail = require("@sendgrid/mail");

async function EmailPlugin(){
    let self = {};
    self.sendEmail = async function(to, from, subject, text, html){
        const msg = {
            to: to,
            from: from,
            subject: subject,
            text: text,
            html: html
        };
        await sgMail.send(msg);
    }
    return self;
}

let singletonInstance = undefined;

module.exports = {
    getInstance: async function () {
        if(!singletonInstance){
            singletonInstance = await EmailPlugin();
        }
        return singletonInstance;
    },
    getAllow: function(){
        return async function(globalUserId, email, command, ...args){
            return true;
        }
    }
}