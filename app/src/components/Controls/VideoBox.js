import React from 'react';
import { withStyles } from '@material-ui/core/styles';
import Box from '@material-ui/core/Box';

const styles = (theme) => ({
	videoBox : (props) => ({
		position           : props.position || 'relative',
		width              : props.width,
		height             : props.height,
		margin             : theme.spacing(props.margin || 0),
		order              : props.order,
		boxShadow          : theme.shadows[10],
		backgroundColor    : 'var(--peer-bg-color)',
		backgroundImage    : 'var(--peer-empty-avatar)',
		backgroundPosition : 'bottom',
		backgroundSize     : 'auto 85%',
		backgroundRepeat   : 'no-repeat',
		borderRadius       : props.roundedCorners ? theme.roundedness : '0'
	})
});

const VideoBox = withStyles(styles)(({ classes, children, ...props }) =>
{
	return (
		<Box className={classes.videoBox} {...props}>
			{children}
		</Box>
	);
});

export default VideoBox;
