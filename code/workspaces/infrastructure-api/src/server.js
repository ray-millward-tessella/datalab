import express from 'express';
import chalk from 'chalk';
import bodyParser from 'body-parser';
import logger from './config/logger';
import config from './config/config';
import routes from './config/routes';
import database from './config/database';

const port = config.get('apiPort');

const app = express();
app.use(bodyParser.json());
routes.configureRoutes(app);

function listen() {
  app.listen(port, () => logger.info(chalk.green(`Management API listening on port ${port}`)));
}

database.createConnection()
  .then(listen)
  .catch(error => logger.error(`Error connecting to the database ${error}`));