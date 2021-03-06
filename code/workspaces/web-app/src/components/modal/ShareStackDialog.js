import React from 'react';
import PropTypes from 'prop-types';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContentText from '@material-ui/core/DialogContentText';
import SecondaryActionButton from '../common/buttons/SecondaryActionButton';

function ShareStackDialog({ onSubmit, title, body, onCancel }) {
  return (
    <Dialog open={true} maxWidth="md">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{body}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <SecondaryActionButton onClick={onSubmit} icon="check">Confirm</SecondaryActionButton>
        <SecondaryActionButton onClick={onCancel} icon="clear">Cancel</SecondaryActionButton>
      </DialogActions>
    </Dialog>
  );
}

ShareStackDialog.propTypes = {
  onSubmit: PropTypes.func.isRequired,
  onCancel: PropTypes.func.isRequired,
  title: PropTypes.string.isRequired,
  body: PropTypes.string.isRequired,
};

export default ShareStackDialog;
