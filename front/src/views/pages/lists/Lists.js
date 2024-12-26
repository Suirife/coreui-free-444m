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

function UserTable() {
  const [users, setUsers] = useState([]);


useEffect(() => {
  // Fetch user data from your database
  fetch('${BASE_DOMAIN}/UserBase') 
    .then(res => res.json())
    .then(data => setUsers(data))
    .catch(error => console.error('Error fetching users:', error));
}, []);

return (
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
          <td>{user.name}</td>
          <td>{user.email}</td>
        </tr>
      ))}
    </tbody>
  </table>
);
}



export default UserTable;
