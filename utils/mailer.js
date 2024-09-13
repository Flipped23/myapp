// utils/mailer.js
const nodemailer = require('nodemailer');

// 创建一个SMTP传输对象
const transporter = nodemailer.createTransport({
    service: '', // 使用Gmail服务
    auth: {
        user: '', // 你的邮箱
        pass: ''   // 你的邮箱密码
    }
});

// 发送邮件的函数
function sendMail(to, subject, text, html) {
    const mailOptions = {
        from: '', // 发件人地址
        to: to,                       // 收件人地址
        subject: subject,             // 邮件主题
        text: text,                   // 纯文本内容
        html: html                    // HTML内容
    };

    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}

module.exports = sendMail;