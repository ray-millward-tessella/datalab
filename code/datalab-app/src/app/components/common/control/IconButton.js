import React from 'react';
import PropTypes from 'prop-types';
import Button from 'material-ui/Button';
import Icon from 'material-ui/Icon';
import { withStyles } from 'material-ui/styles';

function styles(theme) {
  const buttonBaseStyle = {
    margin: theme.spacing.unit,
  };

  return {
    button: {
      ...buttonBaseStyle,
    },
    buttonDanger: {
      ...buttonBaseStyle,
      color: theme.palette.dangerColor,
      backgroundColor: theme.palette.dangerBackgroundColor,
      '&:disabled': {
        color: theme.palette.secondary[200],
      },
      '&:hover': {
        color: theme.palette.common.white,
        backgroundColor: theme.palette.dangerColor,
      },
    },
    icon: {
      marginLeft: theme.spacing.unit,
    },
  };
}

const IconButton = ({ classes, onClick, children, icon, danger = false, disabled }) => (
    <Button
      className={danger ? classes.buttonDanger : classes.button}
      onClick={onClick}
      color={danger ? undefined : 'accent'}
      disabled={disabled}
      raised >
      {children}
      <Icon className={classes.icon} children={icon} />
    </Button>
);

IconButton.propTypes = {
  onClick: PropTypes.func,
  children: PropTypes.string.isRequired,
  icon: PropTypes.string.isRequired,
  danger: PropTypes.bool,
  disabled: PropTypes.bool,
};

export default withStyles(styles)(IconButton);