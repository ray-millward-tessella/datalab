import React from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';

const styles = theme => ({
  outer: {
    backgroundColor: theme.palette.secondary[50],
  },
  inner: {
    maxWidth: 1024,
    marginLeft: 'auto',
    marginRight: 'auto',
    paddingBottom: 40,
  },
});

function DescribeElementSegment({ classes, children, invert }) {
  let segment = (<div className={classes.inner}>{children}</div>);

  if (invert) {
    segment = (<div className={classes.outer}>{segment}</div>);
  }

  return segment;
}

DescribeElementSegment.propTypes = {
  classes: PropTypes.object.isRequired,
  children: PropTypes.oneOfType([
    PropTypes.element,
    PropTypes.arrayOf(PropTypes.element),
  ]).isRequired,
  invert: PropTypes.bool,
};

export default withStyles(styles)(DescribeElementSegment);