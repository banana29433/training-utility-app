const path = require('path')

module.exports = {

    entry: './assets/js/app.js',

    output: {

        filename: 'app.min.js',
        path: path.join(__dirname, 'assets/js')

    },

    mode: 'production',

    target: 'electron-renderer'

}