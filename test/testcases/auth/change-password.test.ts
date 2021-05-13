/**
 * Jest unit test for authentication API's Change Password feature
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import DBTable from '../../datatypes/DBTable';
import TestEnv from '../../TestEnv';
// eslint-disable-next-line node/no-unpublished-import
import MockDate from 'mockdate';
// eslint-disable-next-line node/no-unpublished-import
import * as request from 'supertest';

describe('DELETE /logout/other-sessions - Logout from other sessions', () => {
  let testEnv: TestEnv;
  let refreshToken: string;
  let currentDate: Date;

  beforeAll(() => {
    // Set new timeout
    jest.setTimeout(120000);
  });

  beforeEach(async () => {
    // Setup TestEnv
    testEnv = new TestEnv(expect.getState().currentTestName);

    // Start Test Environment
    const dbTable: DBTable[] = [DBTable.USER, DBTable.SESSION];
    await testEnv.start(dbTable);

    // Create Two more sessions
    currentDate = new Date();
    MockDate.set(currentDate.getTime());
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'Password12!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'Password12!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());

    // Retrieve refreshToken for the user
    const response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'Password12!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];
  });

  afterEach(async () => {
    await testEnv.stop();
    MockDate.reset();
  });

  test('Success - Change Password (Admin User)', async done => {
    // Login with admin user & retrieve refresh token
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'rootpw!!'});
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());

    // Retrieve refreshToken for the user
    let response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'Rootpw12!!'});
    expect(response.status).toBe(200);
    refreshToken = response.header['set-cookie'][1]
      .split('; ')[0]
      .split('=')[1];

    // Password change request
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Rootpw12!!', newPassword: 'newPW129!!'});
    expect(response.status).toBe(200);

    // DB Check - User: Password Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'admin',
      new Date(queryResult[0].membersince).toISOString(),
      'newPW129!!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'admin'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(refreshToken);

    // DB Check - Session: Other user's session not cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session where username = 'user2'"
    );
    expect(queryResult.length).toBe(3);

    // Login with changed password
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'admin', password: 'newPW129!!'});
    expect(response.status).toBe(200);
    done();
  });

  test('Success - Change Password (Non-Admin User)', async done => {
    // Password change request
    let response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPW129!!'});
    expect(response.status).toBe(200);

    // DB Check - User: Password Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user2',
      new Date(queryResult[0].membersince).toISOString(),
      'newPW129!!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    expect(queryResult[0].token).toBe(refreshToken);

    // Login with changed password
    currentDate.setSeconds(currentDate.getSeconds() + 1);
    MockDate.set(currentDate.getTime());
    response = await request(testEnv.expressServer.app)
      .post('/login')
      .send({username: 'user2', password: 'newPW129!!'});
    expect(response.status).toBe(200);
    done();
  });

  test('Fail - Invalid Password', async done => {
    // Password change request
    const response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPW123!!'});
    expect(response.status).toBe(400);

    // DB Check - User: Password Not Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user2',
      new Date(queryResult[0].membersince).toISOString(),
      'Password12!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Not Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(3);
    done();
  });

  test('Fail - Invalid Password (Additional)', async done => {
    // No Number
    let response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPWacf!!'});
    expect(response.status).toBe(400);

    // No Capitals
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'new79129!!'});
    expect(response.status).toBe(400);

    // No small cases
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'NEWPW129!!'});
    expect(response.status).toBe(400);

    // No symbols
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'NEWpw129NW'});
    expect(response.status).toBe(400);

    // Invalid symbols
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPW129??'});
    expect(response.status).toBe(400);

    // Consecutive Letters
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPW123!!'});
    expect(response.status).toBe(400);

    // Consecutive Letters
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPW321!!'});
    expect(response.status).toBe(400);

    // Same Letters
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'newPW111!!'});
    expect(response.status).toBe(400);

    // Same Letters in username
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'serPW111!!'});
    expect(response.status).toBe(400);

    // Same Letters in username - Reverse
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: 'resPW111!!'});
    expect(response.status).toBe(400);

    // Short
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'Password12!', newPassword: '!pW1'});
    expect(response.status).toBe(400);

    // Long
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({
        currentPassword: 'Password12!',
        newPassword:
          'PasswordUser129!!PasswordUser129!!PasswordUser129!!PasswordUser129!!PasswordUser129!!',
      });
    expect(response.status).toBe(400);
    done();
  });

  test('Fail - Invalid Token', async done => {
    // Password change request
    const response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}abcd`])
      .send({currentPassword: 'password12!', newPassword: 'newpw123'});
    expect(response.status).toBe(401);

    // DB Check - User: Password Not Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user2',
      new Date(queryResult[0].membersince).toISOString(),
      'Password12!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Not Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(3);
    done();
  });

  test('Fail - Bad Request', async done => {
    // Password change request with missing field
    let response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'password12!'});
    expect(response.status).toBe(400);
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({newPassword: 'password12!'});
    expect(response.status).toBe(400);

    // Password change request with wrong field name
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPasswordAdd: 'password12!', newPassword: 'newpw123'});
    expect(response.status).toBe(400);

    // Password change request with additional Field
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({
        currentPassword: 'password12!',
        newPassword: 'newpw123',
        id: 'user2',
      });
    expect(response.status).toBe(400);

    // Password change request without body
    response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`]);
    expect(response.status).toBe(400);

    // DB Check - User: Password Not Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user2',
      new Date(queryResult[0].membersince).toISOString(),
      'Password12!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Not Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(3);
    done();
  });

  // TEST: Not Matching Current PW
  test('Fail - Not Matching Current PW', async done => {
    // Password change request
    const response = await request(testEnv.expressServer.app)
      .put('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'wrongPW', newPassword: 'newPW129!!'});
    expect(response.status).toBe(401);

    // DB Check - User: Password Not Changed
    let queryResult = await testEnv.dbClient.query(
      "SELECT * FROM user WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(1);
    const hashedPassword = testEnv.testConfig.hash(
      'user2',
      new Date(queryResult[0].membersince).toISOString(),
      'Password12!'
    );
    expect(queryResult[0].password).toBe(hashedPassword);

    // DB Check - Session: Other Session Not Cleared
    queryResult = await testEnv.dbClient.query(
      "SELECT * FROM session WHERE username = 'user2'"
    );
    expect(queryResult.length).toBe(3);
    done();
  });

  test('Fail - Wrong Method', async done => {
    // Password change request
    const response = await request(testEnv.expressServer.app)
      .trace('/password')
      .set('Cookie', [`X-REFRESH-TOKEN=${refreshToken}`])
      .send({currentPassword: 'password12!', newPassword: 'newpw123'});
    expect(response.status).toBe(405);
    done();
  });
});
