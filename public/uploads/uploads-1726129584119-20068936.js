document.getElementById("my-p").innerHTML = generateRandomStr(10);

function generateRandomStr(length) {
    let result = '';
    let characters =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// 块级作用域
if (true) {
    let x = 5;
}
// 箭头函数
const add = (a, b) => a + b;

// 解构赋值
const person = {name: 'Tom', age: 20};
const {name, age} = person;

// 模板字符串
const greeting = `Hello, my name is ${name}`;

// 模块化
export const square = x => x * x;

// 在main.js中
import {square} from './module.js';
console.log(square(5)); // 输出25