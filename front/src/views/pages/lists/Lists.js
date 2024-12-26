import React from 'react'
import {
  CButton,
  CCol,
  CContainer,
  CFormInput,
  CInputGroup,
  CInputGroupText,
  CRow,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilMagnifyingGlass } from '@coreui/icons'

const UserTable = () => {
  const [users, setUsers] = useState([
    id: string, 
    username: string,
    email: string,
    hashed_password: string,
    is_active: boolean,
    failed_logins: integer,
    access_token: string,
    restore_token: string
  ]);


useEffect(() => {
  // Fetch user data from your database
  fetch('http://203.31.40.135:3001/get_all_users') 
    .then(res => res.json())
    .then(data => setUsers(data))
    .catch(error => console.error('Error fetching users:', error));
}, []);

return (
  <div style={{ padding: '20px', border: '1px solid #ccc' }}>
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Email</th>
      </tr>
    </thead>
    <tbody>
      {users.map(user => (
        <tr key={user.id}>
          <td>{user.username}</td>
          <td>{user.email}</td>
        </tr>
      ))}
    </tbody>
  </table>
 </div>
);
}



export default UserTable;
