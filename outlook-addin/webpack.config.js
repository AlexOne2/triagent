const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const devCerts = require("office-addin-dev-certs");

module.exports = async () => {
  const httpsOptions = await devCerts.getHttpsServerOptions();
  return {
    entry: {
      taskpane: "./src/taskpane/taskpane.ts"
    },
    output: {
      path: path.resolve(__dirname, "dist"),
      filename: "[name].js",
      clean: true
    },
    resolve: {
      extensions: [".ts", ".js"]
    },
    module: {
      rules: [
        {
          test: /\.ts$/,
          exclude: /node_modules/,
          use: "ts-loader"
        },
        {
          test: /\.html$/,
          use: "html-loader"
        },
        {
          test: /\.css$/,
          use: ["style-loader", "css-loader"]
        }
      ]
    },
    plugins: [
      new HtmlWebpackPlugin({
        filename: "taskpane.html",
        template: "./src/taskpane/taskpane.html",
        chunks: ["taskpane"]
      })
    ],
    devServer: {
      static: [
        {
          directory: __dirname
        },
        {
          directory: path.join(__dirname, "dist")
        }
      ],
      headers: {
        "Access-Control-Allow-Origin": "*"
      },
      https: httpsOptions,
      port: 3001
    }
  };
};
