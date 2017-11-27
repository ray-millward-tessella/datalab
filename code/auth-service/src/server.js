import express from 'express';
import chalk from 'chalk';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import logger from 'winston';
import config from './config/config';
import routes from './config/routes';

logger.level = config.get('logLevel');
logger.remove(logger.transports.Console);
logger.add(logger.transports.Console, { timestamp: true, colorize: true });

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
routes.configureRoutes(app);

app.use((error, request, response, next) => { // eslint-disable-line no-unused-vars
  if (error.name === 'UnauthorizedError') {
    logger.warn(`Unsuccessful authentication request from ${request.hostname}`);
    response.status(401);
    return response.send({ message: 'Unable to authenticate user' });
  }

  logger.error(error.message);
  response.status(500);
  return response.send({ message: 'Error authenticating user' });
});

const port = config.get('port');
app.listen(port, () => logger.info(chalk.green(`Authorisation Service listening on port ${port}`)));