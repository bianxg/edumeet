import React from 'react';
import { connect } from 'react-redux';
import { withStyles } from '@material-ui/core/styles';
import { withRoomContext } from '../../RoomContext';
import * as settingsActions from '../../store/actions/settingsActions';
import PropTypes from 'prop-types';
import classnames from 'classnames';
import { useIntl, FormattedMessage } from 'react-intl';
import MenuItem from '@material-ui/core/MenuItem';
import FormHelperText from '@material-ui/core/FormHelperText';
import FormControl from '@material-ui/core/FormControl';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Select from '@material-ui/core/Select';
import Switch from '@material-ui/core/Switch';
import { config } from '../../config';

import Resizer from 'react-image-file-resizer';
import ImageUploader from 'react-images-upload';

const styles = (theme) =>
	({
		setting :
		{
			padding : theme.spacing(2)
		},
		formControl :
		{
			display : 'flex'
		},
		switchLabel : {
			justifyContent : 'space-between',
			flex           : 'auto',
			display        : 'flex',
			padding        : theme.spacing(1),
			marginRight    : 0
		}
	});

const AdvancedSettings = ({
	roomClient,
	settings,
	onToggleAdvancedMode,
	onToggleNotificationSounds,
	classes
}) =>
{
	const intl = useIntl();

	const onDrop = (picture) =>
	{
		if (picture.length > 0)
		{
			Resizer.imageFileResizer(picture[0], 1280, 720, 'JPEG', 99, 0,
				(uri) =>
				{
					const reader = new FileReader();

					reader.addEventListener('load', () =>
					{
						roomClient.setPicture(reader.result);
					});
					reader.readAsDataURL(uri);
				},
				'blob');
		}
		else
		{
			roomClient.setPicture(null);
		}
	};

	return (
		<React.Fragment>
			<ImageUploader
				withIcon
				onChange={onDrop}
				imgExtension={[ '.jpg', '.jpeg', '.png' ]}
				maxFileSize={5242880}
				singleImage
				withPreview
				defaultImages={settings.localPicture?[ settings.localPicture ]:[]}
				buttonType='button'
				buttonText={intl.formatMessage({
					id             : 'settings.myPhotoButton',
					defaultMessage : 'Set my photo'
				})}
				label={intl.formatMessage({
					id             : 'settings.myPhotoLabel',
					defaultMessage : 'Max. file size: 5MB, accepted: jpg, jpeg, png'
				})}
				fileSizeError={intl.formatMessage({
					id             : 'settings.myPhotoSizeError',
					defaultMessage : ' file is too large'
				})}
				fileTypeError={intl.formatMessage({
					id             : 'settings.myPhotoTypeError',
					defaultMessage : ' is not a supported file extension'
				})}
			/>
			<FormControlLabel
				className={classnames(classes.setting, classes.switchLabel)}
				control={<Switch checked={settings.advancedMode} onChange={onToggleAdvancedMode} value='advancedMode' />}
				labelPlacement='start'
				label={intl.formatMessage({
					id             : 'settings.advancedMode',
					defaultMessage : 'Advanced mode'
				})}
			/>
			<FormControlLabel
				className={classnames(classes.setting, classes.switchLabel)}
				control={<Switch checked={settings.notificationSounds} onChange={onToggleNotificationSounds} value='notificationSounds' />}
				labelPlacement='start'
				label={intl.formatMessage({
					id             : 'settings.notificationSounds',
					defaultMessage : 'Notification sounds'
				})}
			/>
			{ !config.lockLastN &&
				<form className={classes.setting} autoComplete='off'>
					<FormControl className={classes.formControl}>
						<Select
							value={settings.lastN || ''}
							onChange={(event) =>
							{
								if (event.target.value)
									roomClient.changeMaxSpotlights(event.target.value);
							}}
							name='Last N'
							autoWidth
							className={classes.selectEmpty}
						>
							{ Array.from(
								{ length: config.maxLastN || 10 },
								(_, i) => i + 1
							).map((lastN) =>
							{
								return (
									<MenuItem key={lastN} value={lastN}>
										{lastN}
									</MenuItem>
								);
							})}
						</Select>
						<FormHelperText>
							<FormattedMessage
								id='settings.lastn'
								defaultMessage='Number of visible videos'
							/>
						</FormHelperText>
					</FormControl>
				</form>
			}
		</React.Fragment>
	);
};

AdvancedSettings.propTypes =
{
	roomClient                 : PropTypes.any.isRequired,
	settings                   : PropTypes.object.isRequired,
	onToggleAdvancedMode       : PropTypes.func.isRequired,
	onToggleNotificationSounds : PropTypes.func.isRequired,
	classes                    : PropTypes.object.isRequired
};

const mapStateToProps = (state) =>
	({
		settings : state.settings
	});

const mapDispatchToProps = {
	onToggleAdvancedMode       : settingsActions.toggleAdvancedMode,
	onToggleNotificationSounds : settingsActions.toggleNotificationSounds
};

export default withRoomContext(connect(
	mapStateToProps,
	mapDispatchToProps,
	null,
	{
		areStatesEqual : (next, prev) =>
		{
			return (
				prev.settings === next.settings
			);
		}
	}
)(withStyles(styles)(AdvancedSettings)));