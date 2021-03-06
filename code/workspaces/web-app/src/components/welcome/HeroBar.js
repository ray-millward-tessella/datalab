import React from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import datalabsLogo from '../../assets/images/datalabs-vert.png';
import getAuth from '../../auth/auth';
import PrimaryActionButton from '../common/buttons/PrimaryActionButton';
import PagePrimaryActionButton from '../common/buttons/PagePrimaryActionButton';

const styles = theme => ({
  bar: {
    backgroundColor: theme.palette.backgroundDark,
    textAlign: 'center',
    zIndex: 2,
    padding: `${theme.spacing(14)}px ${theme.spacing(2)}px`,
  },
  logo: {
    height: 300,
  },
  tagLine: {
    color: theme.palette.secondary[50],
    padding: 20,
  },
  buttons: {
    display: 'flex',
    justifyContent: 'center',
    margin: `${theme.spacing(4)}px ${theme.spacing(1)}px`,
    marginBottom: 0,
  },
  button: {
    '& + &': {
      marginLeft: theme.spacing(2),
    },
  },
});

const tagLine = 'DataLabs provides you with tools to power your research and share the results';

const HeroBar = ({ classes }) => (
  <div className={classes.bar}>
    <img className={classes.logo} src={datalabsLogo} alt="DataLabs-Logo" />
    <Typography className={classes.tagLine} variant="h6">{tagLine}</Typography>
    <div className={classes.buttons}>
      <PagePrimaryActionButton className={classes.button} color="primary" onClick={getAuth().signUp}>Sign Up</PagePrimaryActionButton>
      <PrimaryActionButton className={classes.button} color="primary" onClick={getAuth().login}> Log In</PrimaryActionButton>
    </div>
  </div>
);

HeroBar.propTypes = {
  classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(HeroBar);
