import { bindActionCreators } from 'redux';
import { connect } from 'react-redux';
import { reset } from 'redux-form';
import Promise from 'bluebird';
import PropTypes from 'prop-types';
import React, { Component } from 'react';
import { permissionTypes } from 'common';
import { MODAL_TYPE_CONFIRMATION, MODAL_TYPE_LOGS, MODAL_TYPE_SHARE_STACK } from '../../constants/modaltypes';
import modalDialogActions from '../../actions/modalDialogActions';
import notify from '../../components/common/notify';
import currentProjectSelectors from '../../selectors/currentProjectSelectors';
import stackActions from '../../actions/stackActions';
import StackCards from '../../components/stacks/StackCards';
import userActions from '../../actions/userActions';

const refreshTimeout = 15000;

const { projectPermissions: { PROJECT_KEY_STACKS_CREATE, PROJECT_KEY_STACKS_DELETE, PROJECT_KEY_STACKS_OPEN, PROJECT_KEY_STACKS_EDIT }, projectKeyPermission } = permissionTypes;

class StacksContainer extends Component {
  constructor(props, context) {
    super(props, context);
    this.openStack = this.openStack.bind(this);
    this.createStack = this.createStack.bind(this);
    this.openCreationForm = this.openCreationForm.bind(this);
    this.deleteStack = this.deleteStack.bind(this);
    this.confirmDeleteStack = this.confirmDeleteStack.bind(this);
    this.shareStack = this.shareStack.bind(this);
    this.confirmShareStack = this.confirmShareStack.bind(this);
    this.loadStack = this.loadStack.bind(this);
    this.updateStack = this.updateStack.bind(this);
    this.setUpdateTimeout = this.setUpdateTimeout.bind(this);
  }

  openStack(stack) {
    return this.props.actions.getUrl(this.props.projectKey.value, stack.id)
      .then(payload => this.props.actions.openStack(payload.value.redirectUrl))
      .catch(err => notify.error(`Unable to open ${this.props.typeName}`));
  }

  getLogs = stack => this.props.actions.openModalDialog(MODAL_TYPE_LOGS, {
    title: 'Logs',
    projectName: stack.projectKey,
    stackName: stack.name,
    onCancel: this.props.actions.closeModalDialog,
    getLogs: this.props.actions.getLogs,
  });

  createStack = stack => Promise.resolve(this.props.actions.closeModalDialog())
    .then(() => this.props.actions.createStack({ ...stack, projectKey: this.props.projectKey.value }))
    .then(() => this.props.actions.resetForm(this.props.formStateName))
    .then(() => notify.success(`${this.props.typeName} created`))
    .catch(err => notify.error(`Unable to create ${this.props.typeName}`))
    .finally(() => this.props.actions.loadStacksByCategory(this.props.projectKey.value, this.props.containerType));

  shareStack = (stack, shared) => Promise.resolve(this.props.actions.closeModalDialog())
    .then(() => this.props.actions.updateStackShareStatus({ ...stack, shared }))
    .then(() => notify.success(`Resource: ${stack.name} is now shared`))
    .finally(() => this.props.actions.loadStacksByCategory(this.props.projectKey.value, this.props.containerType));

  confirmShareStack = (stack, shared) => this.props.actions.openModalDialog(MODAL_TYPE_SHARE_STACK, {
    title: `Share ${this.props.typeName}`,
    body: `Please confirm you wish to share the ${stack.displayName} ${this.props.typeName} with other users within the project. 
      WARNING: This action cannot currently be reversed.`,
    onCancel: this.props.actions.closeModalDialog,
    onSubmit: () => this.shareStack(stack, 'project'),
  });

  openCreationForm = () => this.props.actions.openModalDialog(this.props.dialogAction, {
    title: `Create a ${this.props.typeName}`,
    projectKey: this.props.projectKey.value,
    onSubmit: this.createStack,
    onCancel: this.props.actions.closeModalDialog,
  });

  deleteStack = stack => Promise.resolve(this.props.actions.closeModalDialog())
    .then(() => this.props.actions.deleteStack(stack))
    .then(() => notify.success(`${this.props.typeName} deleted`))
    .catch(err => notify.error(`Unable to delete ${this.props.typeName}`))
    .finally(() => this.props.actions.loadStacksByCategory(this.props.projectKey.value, this.props.containerType));

  confirmDeleteStack = stack => this.props.actions.openModalDialog(MODAL_TYPE_CONFIRMATION, {
    title: `Delete ${stack.displayName} ${this.props.typeName}`,
    body: `Would you like to delete the ${stack.displayName} ${this.props.typeName}? Any saved work will continue to be
        stored in the shared drive.`,
    onSubmit: () => this.deleteStack(stack),
    onCancel: this.props.actions.closeModalDialog,
  });

  loadStack() {
    // Added .catch to prevent unhandled promise error, when lacking permission to view content
    return this.props.actions.loadStacksByCategory(this.props.projectKey.value, this.props.containerType)
      .then(() => { this.setUpdateTimeout(); })
      .catch((() => {}));
  }

  updateStack() {
    this.props.actions.updateStacksByCategory(this.props.projectKey.value, this.props.containerType)
      .then(() => {
        this.setUpdateTimeout();
      })
      .catch(() => {});
  }

  setUpdateTimeout() {
    // If project key changes in state, another timer seemed to be being created
    // rather than replacing the existing one (would still timeout when navigating to
    // a different page). Clearing the timeout first seems to solve the issue.
    if (this.timeout) {
      clearTimeout(this.timeout);
    }
    this.timeout = setTimeout(this.updateStack, refreshTimeout);
  }

  componentDidMount() {
    this.props.actions.listUsers();
    if (this.props.projectKey.value) {
      this.loadStack();
    }
  }

  componentWillUnmount() {
    clearTimeout(this.timeout);
  }

  shouldComponentUpdate(nextProps) {
    return !nextProps.stacks.updating;
  }

  componentDidUpdate(prevProps) {
    if (this.props.projectKey.value !== prevProps.projectKey.value) {
      this.loadStack();
    }
  }

  render() {
    const stacksUpdatedFetching = {
      ...this.props.stacks,
      fetching: this.props.stacks.fetching || this.props.projectKey.fetching,
    };
    return (
      <StackCards
        stacks={stacksUpdatedFetching}
        typeName={this.props.typeName}
        typeNamePlural={this.props.typeNamePlural}
        getLogs={this.getLogs}
        openStack={this.openStack}
        deleteStack={this.confirmDeleteStack}
        shareStack={this.confirmShareStack}
        openCreationForm={this.openCreationForm}
        userPermissions={() => this.props.userPermissions}
        createPermission={projectKeyPermission(PROJECT_KEY_STACKS_CREATE, this.props.projectKey.value)}
        openPermission={projectKeyPermission(PROJECT_KEY_STACKS_OPEN, this.props.projectKey.value)}
        deletePermission={projectKeyPermission(PROJECT_KEY_STACKS_DELETE, this.props.projectKey.value)}
        editPermission={projectKeyPermission(PROJECT_KEY_STACKS_EDIT, this.props.projectKey.value)} />
    );
  }
}

StacksContainer.propTypes = {
  stacks: PropTypes.shape({
    error: PropTypes.any,
    fetching: PropTypes.bool.isRequired,
    value: PropTypes.array.isRequired,
  }).isRequired,
  typeName: PropTypes.string.isRequired,
  typeNamePlural: PropTypes.string,
  containerType: PropTypes.string.isRequired,
  dialogAction: PropTypes.string.isRequired,
  formStateName: PropTypes.string.isRequired,
  actions: PropTypes.shape({
    loadStacksByCategory: PropTypes.func.isRequired,
    getUrl: PropTypes.func.isRequired,
    openStack: PropTypes.func.isRequired,
    createStack: PropTypes.func.isRequired,
    deleteStack: PropTypes.func.isRequired,
    openModalDialog: PropTypes.func.isRequired,
    closeModalDialog: PropTypes.func.isRequired,
    getLogs: PropTypes.func,
    shareStack: PropTypes.func,
  }).isRequired,
  userPermissions: PropTypes.arrayOf(PropTypes.string).isRequired,
  projectKey: PropTypes.object.isRequired,
};

function mapStateToProps(state) {
  return {
    stacks: state.stacks,
    projectKey: currentProjectSelectors.currentProjectKey(state),
  };
}

function mapDispatchToProps(dispatch) {
  return {
    actions: bindActionCreators({
      ...stackActions,
      ...modalDialogActions,
      ...userActions,
      resetForm: formStateName => reset(formStateName),
    }, dispatch),
  };
}

export { StacksContainer as PureStacksContainer }; // export for testing
export default connect(mapStateToProps, mapDispatchToProps)(StacksContainer);
