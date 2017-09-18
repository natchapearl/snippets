//Password Reset: Salt and Hash

//Get the salt key from database to check if the current password is correct. If there is a match, the salt key will then be hashed to the new password and stored in the database.


        public void UpdatePasswordForLoggedInUser(PasswordUpdateRequest model)
        {
            dataProvider.ExecuteCmd("dbo.Users_SelectPwSaltById"
               , inputParamMapper: delegate (SqlParameterCollection paramCollection)
               {
                   paramCollection.AddWithValue("@Id", model.Id);
               }

            , singleRecordMapper: delegate (IDataReader reader, short set)
              {
                  // get the current password from the result set
                  string currentPassword = reader.GetSafeString(0);
                  // get the salt from the database
                  string salt = reader.GetSafeString(1);
                  // hash the old password guess that the user specified
                  string passwordHash = _cryptographyService.Hash(model.OldPassword, salt, HASH_ITERATION_COUNT);

                  if (passwordHash == currentPassword)
                  {
                      // if we get here, the user knew their old password 

                      // do the stored procedure call to update the password in the DB
                      dataProvider.ExecuteNonQuery("dbo.Users_InsertUpdatedPassword"
                         , inputParamMapper: delegate (SqlParameterCollection paramCollection)
                         {
                             // pass in a parameter for the user ID
                             paramCollection.AddWithValue("@Id", model.Id);

                             // hash the user's new password and store it in a variable
                             string newPasswordHash = _cryptographyService.Hash(model.NewPassword, salt, HASH_ITERATION_COUNT);

                             // pass in a parameter for the hashed new password
                             paramCollection.AddWithValue("@NewPasswordHash", newPasswordHash);
                         });
                  }
                  else
                  {
                      throw new InvalidPasswordException();
                  }
              });
        }