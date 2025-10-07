import React from 'react';

function UserProfile({ userBio }) {
    return (
        <div dangerouslySetInnerHTML={{__html: userBio}} />
    );
}

export default UserProfile;