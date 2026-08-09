## UsersV1

UserService provides access to eGordian data using a REST API. All data will be retrieved beginning at the Users and drilling down into the appropriate objects. 
All data will implement existing security from eGordian at the object/field level and be applied at the service level.

|API|Description|
|--|--|
|GET v1/Users|Serach Job Orders with filters that are accessble to the User|
|GET v1/Users/{userId}|Gets single user by userId|

## CompanyForm
|API|Description|
|--|--|
|GET v1/Companies/{companyId}/Forms/{formId}|Gets the form for company.|
|GET v1/Companies/{companyId}|Gets the company information.|

## AccessToken

AccessTokenController returns access token to consume API Services.

|API|Description|
|--|--|
|GET api/AccessToken|Return Access Token|

## HealthCheck

Health Check Controller

|API|Description|
|--|--|
|GET api/HealthCheck/RefreshCache|Clealr all cache items..|

## ContactsV1

Provide access to eGordian contacts data using a REST API.
All data will implement existing security from eGordian at the object/field level and be applied at the service level.

|API|Description|
|--|--|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts|JobOrderContactListByOwner => Get Job Order Contact List that are accessble to the User|
|GET v1/Owners/{ownerId}/Contacts|ContactListByOwner => Get Owner Contact List that are accessble to the User|
|GET v1/Owners/{ownerId}/Contacts/{contactId}|JobOrderContactDetails => Get a specific Job Order Contact with with Contact Id|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts/{contactId}|JobOrderContactDetails => Get a specific Job Order Contact with with Contact Id|
|PUT v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts/{contactId}|JobOrderContact-Update => This will save the contact object provided in the payload|
|PUT v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts/{contactId}/roleId/{roleId}|JobOrderContact-Update => This will save the contact object provided in the payload|
|DELETE v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts/{contactId}|JobOrderContact-Remove Contact from Job Order => This will remove the contact object for the given contact id in the URL|
|PUT v1/Owners/{ownerId}/Contacts/{contactId}|update a contact object for an owner|
|POST v1/Owners/{ownerId}/Contacts|save a contact object for an owner|
|GET v1/Users/{userId}/Contacts/{contactId}|Get a specific Job Order Contact with with Contact Id|
|GET v1/Users/{userId}/Contacts|User Contact Search And List of contact for user|
|POST v1/Owners/{ownerId}/JobOrders/{jobId}/Contacts/{contactId}/roleId/{roleId}|JobOrderContact-Remove Contact from Job Order => This will save the contact object provided in the payload|

## PicturesV1

Picture service provides access to eGordian data using a REST API. All data will be retrieved beginning at the picture and drilling down into the appropriate objects. 
All data will implement existing security from eGordian at the object/field level and be applied at the service level.

|API|Description|
|--|--|
|GET v1/Pictures|Gets the list of pictures|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/Pictures|Gets pictures for a job order.|
|GET v1/Pictures/{pictureId}|Gets the pertucular picture by Id|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/Pictures/{pictureId}/Download|Downloads the full size picture and returns ByteArrayContent.|
|PUT v1/Owners/{ownerId}/Pictures/{pictureId}/{pictureName}|Update pictures Display name|
|POST v1/Owners/{ownerId}/JobOrders/{jobId}/uploadPictures|This will give the ability to upload pictures to a job order|
|POST v1/Owners/{ownerId}/JobOrders/{jobId}/AttachPictures|This will give the ability to attach pictures to a job order|
|DELETE v1/Owners/{ownerId}/JobOrders/{jobId}/Pictures|This will give the ability to delete pictures of a job order To delete picture just pass picture current ID in form body as -[{"Id":103351},{"Id":103352}]|
|DELETE v1/Owners/{ownerId}/JobOrders/{jobId}/Pictures/{pictureId}|No documentation available.|
|POST v1/Owners/{ownerId}/JobOrders/{jobId}/Pictures|This will give the ability to move pictures from a job order to another Joborder To move picture just pass picture current ID in form body as -[{"Id":103351},{"Id":103352}] and JObid in Url|
|POST v1/Owners/{ownerId}/JobOrders/{jobId}/SharePictures|This will give the ability to share pictures between owner and constractor|
|GET v1/Users/{userId}/Pictures|Get User Pictures using UserId from the UserContext|
|GET v1/Users/{userId}/Pictures/{pictureId}|Get the User Picture base on the Id of the Picture|
|POST v1/Users/{userId}/Pictures|This gives the ability to upload pictures to a given user.The payload will be a list of attached images.|
|PUT v1/Users/{userId}/Pictures/{id}/{newName}/{fileExtension}|This will only allow changing the picture name|
|DELETE v1/Users/{userId}/Pictures|This will delete the picture for the user Id in the header of the request if no pictures ID being passed. This function can delete all user pictures/ selected multiple user pictures. To delete selected multiple pictures, picture ID/s need to be passed as formbody  Validation will consist of matching the user Id of the request to the user Id of the picture|
|DELETE v1/Users/{userId}/Pictures/{pictureId}|This will delete the picture for the userpicture Id in the header of the request.  Validation will consist of matching the user Id of the request to the user Id of the picture|

## OwnersV1

Provide access to eGordian data using a REST API. All data will be retrieved beginning at the owner and drilling down into the appropriate objects. 
All data will implement existing security from eGordian at the object/field level and be applied at the service level.

|API|Description|
|--|--|
|GET v1/Owners|Gets the list of Owner|
|GET v1/Owners/{ownerId}|Gets the perticular Owner|
|GET v1/Owners/{ownerId}/Roles|Gets the roles for owner.|
|GET v1/Owners/{ownerId}/Status|Gets the Status for owner.|
|GET v1/Owners/{ownerId}/Companies|Gets the Companies for owner.|

## Requestor
|API|Description|
|--|--|
|GET v1/Requestors/IsRequireMemberImport|No documentation available.|

## TrackingDatesV1

Provide access to eGordian tracking dates data using a REST API.

|API|Description|
|--|--|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/TrackingDates|Gets tracking dates for a job order.|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/TrackingDates/{trackingDateId}|Gets the Tracking Date|
|PUT v1/Owners/{ownerId}/JobOrders/{jobId}/TrackingDates/{trackingDateId}|This will save the tracking date value|

## FilesV1

Provide access to eGordian files data using a REST API.

|API|Description|
|--|--|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/Files|The user of the mobile application or any other application that would request information from eGordian about the DSOW would expect any files that are attached to the DSOW to be returned as part of the request. In addition, any links provided would also be returned.|
|PUT v1/Owners/{ownerId}/JobOrders/{jobId}/Files|This API provides the functionality to share the Files among the Contructor  In addition, any links provided would also be returned.|

## ConstructionTaskCatalogV1

Provide access to eGordian ctc data using a REST API.

|API|Description|
|--|--|
|GET v1/Owners/{ownerId}/Catalogs|Get Owner Catalogs that are accessble to the Owner|
|GET v1/Owners/{ownerId}/Category/{catalogId}|Get Category for OwnerId and CatelogId|
|GET v1/Owners/{ownerId}/CatalogChildNodes/{catalogId}/{hierachyCode}|Gets the url that return child task|
|GET v1/Owners/{ownerId}/TaskData/{catalogId}/{hierachyCode}?searchTerm={searchTerm}|Get the url that return actual task data|

## ThirdPartyMembers

EzIQC ThirdParty Members Controller

|API|Description|
|--|--|
|GET v1/ThirdPartyMembers/{idNumber}|Get ThirdParty Member Informnation for given Memebr ID Number|

## JobOrdersV1

JobOrder Service provides access to eGordian data using a REST API. All data will be retrieved beginning at the Job Order and drilling down into the appropriate objects.

|API|Description|
|--|--|
|GET v1/JobOrders|Gets the list of job Orders|
|GET v1/JobOrders/{jobOrderId}|Gets the pertucular job order by Id|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}|JobOrderDetails => Get a specific Job Order with Job Id|
|GET v1/Owners/{ownerId}/JobOrders|JobOrderListByOwner => Search Job Orders that accessible to a given Owner|
|GET v1/Users/{userId}/JobOrders|JobOrderListByUser => Search Job Orders that accessible to a given user|
|PUT v1/Owners/{ownerId}/JobOrders/{jobId}|Update existing Job Order|
|GET v1/Owners/{ownerId}/JobOrders/{jobId}/DetailedScope|GetDetailScopeOfWork|
|PUT v1/Owners/{ownerId}/JobOrders/{jobId}/DetailedScope|Update the Detail Scope of Work for a job Order|

## JobOrders
|API|Description|
|--|--|
|GET v1/JobRequestsCount|Get Job Order Requests|
|GET v1/JobRequests|Gets the job requests.|
|POST v1/JobRequests|Create a Job Order in EzIqc of type|

## NotesV1

UserService provides access to eGordian job notes data using a REST API.

|API|Description|
|--|--|
|GET v1/Users/{userId}/JobOrders/{jobId}/Notes|This will return a job note list object for the given job order.  The note will not be in the list if the note is hidden and the user Id of the note is not the current user Id.  The default sort will be by Updated Date then by Created Date.|
|POST v1/Users/{userId}/JobOrders/{jobId}/Notes|This will allow saving a new job note for the given job order.  If the job note Id is not zero, a Bad Request will be returned with an error response object.|
|DELETE v1/Users/{userId}/JobOrders/{jobId}/Notes/{noteId}|This will allow deleting an existing job note for the given job order. Only the author of the note can delete the note.  This will mark the note as deleted in the database|
|PUT v1/Users/{userId}/JobOrders/{jobId}/Notes/{noteId}|This will allow updating an existing job note for the given job order. Validation will include the same validation as inserting as well as ensure the user updating the note is the original author.|

## PriceProposalsV1

Provide access to eGordian price proposals data using a REST API.

|API|Description|
|--|--|
|GET v1/Owners/{ownerId}/PriceProposals|Gets the price proposals.|