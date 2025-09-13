const path = require('path');

module.exports = {
    entry: './assets/js/app.js',
    output: {
        filename: 'app.min.js',
        path: path.resolve(__dirname, 'assets/js/dist')
    },
    mode: 'production',
    target: 'electron-renderer',
    module: {
        rules: [
            {
                test: /\.css$/i,
                use: ['style-loader', 'css-loader'],
            },
            {
                test: /\.(woff|woff2|eot|ttf|otf)$/i,
                type: 'asset/resource',
            },
        ],
    },
};