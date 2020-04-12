from ma import ma
from models.user import UserModel

class UserSchema(ma.ModelSchema):
    class Meta:
        model = UserModel
        load_only = ("password",) # make sure of the tuple by the , in the end.
        dump_only = ("id",)