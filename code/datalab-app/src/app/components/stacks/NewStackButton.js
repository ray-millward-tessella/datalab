import React from 'react';
import PropTypes from 'prop-types';
import { Card, Image } from 'semantic-ui-react';
import plusIcon from '../../../assets/images/plus.svg';

const containerStyle = { width: '100%', height: '100%', background: 'grey', color: 'white', cursor: 'pointer' };
const contentStyle = { width: '50%', margin: 'auto', marginTop: '50px', marginBottom: '50px' };

const NewStackButton = ({ onClick, typeName }) =>
  <Card>
    <div style={containerStyle} onClick={onClick}>
      <div style={contentStyle}>
        <Image centered size='tiny' src={plusIcon} />
        <h3>Create {typeName}</h3>
      </div>
    </div>
  </Card>;

NewStackButton.propTypes = {
  onClick: PropTypes.func,
  typeName: PropTypes.string.isRequired,
};

export default NewStackButton;